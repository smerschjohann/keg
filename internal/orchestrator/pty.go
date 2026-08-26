package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// isTerminal reports whether f is connected to a terminal (TTY).
func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	return err == nil
}

// openPTY allocates a new pseudo-terminal master/slave pair.
// The caller must close both files when done.
func openPTY() (master, slave *os.File, err error) {
	masterFD, oerr := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if oerr != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", oerr)
	}
	master = os.NewFile(uintptr(masterFD), "ptmx")
	cleanup := func() { _ = master.Close() }

	// unlockpt: clear the slave lock so it can be opened.
	// TIOCSPTLCK expects a pointer to an int (not the int itself).
	var lock int32
	if _, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(masterFD),
		unix.TIOCSPTLCK,
		uintptr(unsafe.Pointer(&lock)), // #nosec G103 -- kernel TIOCSPTLCK ioctl
	); errno != 0 {
		cleanup()
		return nil, nil, fmt.Errorf("unlockpt (TIOCSPTLCK): %w", errno)
	}

	// Try TIOCGPTPEER first (Linux ≥ 4.13): opens the slave without a path lookup.
	slaveFD, err := unix.IoctlRetInt(masterFD, unix.TIOCGPTPEER|unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC)
	if err != nil {
		// Fallback for older kernels: resolve via TIOCGPTN + /dev/pts/<n>.
		var n uint32
		if _, _, errno := syscall.Syscall(
			syscall.SYS_IOCTL,
			uintptr(masterFD),
			unix.TIOCGPTN,
			uintptr(unsafe.Pointer(&n)), // #nosec G103 -- kernel TIOCGPTN ioctl
		); errno != 0 {
			cleanup()
			return nil, nil, fmt.Errorf("TIOCGPTN: %w", errno)
		}
		slavePath := fmt.Sprintf("/dev/pts/%d", n)
		slaveFD2, serr := unix.Open(slavePath, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if serr != nil {
			cleanup()
			return nil, nil, fmt.Errorf("open slave %s: %w", slavePath, serr)
		}
		slave = os.NewFile(uintptr(slaveFD2), slavePath)
		return master, slave, nil
	}
	slave = os.NewFile(uintptr(slaveFD), "pts-peer")
	return master, slave, nil
}

// setWindowSize applies cols×rows to the PTY at f via TIOCSWINSZ.
func setWindowSize(f *os.File, cols, rows uint16) error {
	ws := unix.Winsize{Col: cols, Row: rows}
	return unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, &ws)
}

// getWindowSize reads the terminal dimensions of f.
func getWindowSize(f *os.File) (cols, rows uint16, err error) {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0, err
	}
	return ws.Col, ws.Row, nil
}

// makeRaw puts f into raw mode and returns the original termios for restore.
// Returns nil, nil when f is not a terminal or when IoctlGetTermios fails.
func makeRaw(f *os.File) (*unix.Termios, error) {
	orig, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		return nil, nil //nolint:nilerr // non-terminal: silently skip
	}
	raw := *orig
	// cfmakeraw: clear ICANON, ECHO, ISIG; set VMIN=1, VTIME=0.
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, &raw); err != nil {
		return nil, fmt.Errorf("set raw mode: %w", err)
	}
	return orig, nil
}

// restoreTermios restores the terminal to its saved state.
func restoreTermios(f *os.File, state *unix.Termios) {
	if state != nil {
		_ = unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, state)
	}
}

// runGuestCommandMaybePTY is the PTY-aware entry point used by guestMain.
// When os.Stdin is a terminal it allocates a PTY pair and runs argv with a
// proper controlling terminal (enabling TUI apps, bash readline, agy, …).
// When stdin is a pipe or file it falls back to the plain runGuestCommand path.
func runGuestCommandMaybePTY(argv []string, stdout, stderr io.Writer) int {
	if !isTerminal(os.Stdin) {
		return runGuestCommandWithStdio(argv, os.Stdin, stdout, stderr)
	}
	return runGuestCommandPTY(argv)
}

// runGuestCommandPTY runs argv with a fresh PTY. It:
//  1. Allocates a master/slave PTY pair.
//  2. Copies the real terminal's window size onto the master.
//  3. Puts the real terminal into raw mode.
//  4. Starts argv with the slave as its controlling terminal.
//  5. Relays bytes between the PTY master and the real terminal.
//  6. Forwards SIGWINCH so full-screen apps track resize events.
func runGuestCommandPTY(argv []string) int {
	master, slave, err := openPTY()
	if err != nil {
		fmt.Fprintf(os.Stderr, "keg guest: openpty: %v\n", err)
		return runGuestCommandWithStdio(argv, os.Stdin, os.Stdout, os.Stderr)
	}
	// slave is passed to the child; we close our copy after the child starts.
	defer func() { _ = master.Close() }()

	// Propagate host terminal dimensions.
	if cols, rows, werr := getWindowSize(os.Stdin); werr == nil {
		_ = setWindowSize(master, cols, rows)
	}

	// Raw mode on the real terminal: keystrokes reach the child unfiltered.
	origTermios, _ := makeRaw(os.Stdin)
	defer restoreTermios(os.Stdin, origTermios)

	// Build the command with slave as its stdio and a new session/ctty.
	// CommandContext with Background: the guest wrapper's own lifetime governs
	// shutdown (signal forwarding + cmd.Wait below), not an external context.
	cmd := exec.CommandContext(context.Background(), argv[0], argv[1:]...) // #nosec G204 -- trusted caller
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.Env = buildWorkloadEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    0, // fd 0 of the child = slave
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "keg guest: exec %s: %v\n", argv[0], err)
		return 127
	}
	// Drop our copy of the slave — only the child holds it now.
	_ = slave.Close()

	// Forward SIGWINCH: host resize → PTY master.
	winchCh := make(chan os.Signal, 1)
	signal.Notify(winchCh, syscall.SIGWINCH)
	stopWinch := make(chan struct{})
	go func() {
		defer signal.Stop(winchCh)
		for {
			select {
			case <-stopWinch:
				return
			case <-winchCh:
				if cols, rows, werr := getWindowSize(os.Stdin); werr == nil {
					_ = setWindowSize(master, cols, rows)
				}
			}
		}
	}()

	// Relay: master ↔ real terminal.
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		_, _ = io.Copy(os.Stdout, master)
	}()
	go func() {
		_, _ = io.Copy(master, os.Stdin)
	}()

	// Forward signals (except SIGWINCH/SIGCHLD which are handled above).
	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGCHLD || sig == syscall.SIGWINCH {
				continue
			}
			_ = cmd.Process.Signal(sig)
		}
	}()

	err = cmd.Wait()
	close(stopWinch)
	// master.Close() in defer triggers EOF in the relay goroutines.
	<-relayDone

	return guestExitCode(err)
}

// runGuestCommandWithStdio runs argv with explicit stdio handles — the plain,
// non-PTY path used for non-interactive invocations and by tests.
func runGuestCommandWithStdio(argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "keg guest: no command given")
		return 127
	}
	cmd := exec.CommandContext(context.Background(), argv[0], argv[1:]...) // #nosec G204 -- trusted caller
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = buildWorkloadEnv()

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "keg guest: exec %s: %v\n", argv[0], err)
		return 127
	}

	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh)
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGCHLD {
				continue
			}
			_ = cmd.Process.Signal(sig)
		}
	}()

	return guestExitCode(cmd.Wait())
}

// guestExitCode maps a cmd.Wait error onto a conventional exit code:
// 0 on success, child code verbatim, signal death as 128+signum, 127 otherwise.
func guestExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return 127
	}
	if code := ee.ExitCode(); code >= 0 {
		return code
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return 127
	}
	return 128 + int(ws.Signal())
}
