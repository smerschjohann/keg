// keg-poc — minimaler Proof of Concept für den Socketpair-Durchstich.
//
// Ein Binary, zwei Rollen (gesteuert per Env-Var, kein reexec nötig):
//
//	HOST:   erzeugt zwei Unix-Socketpairs, startet sich selbst via bwrap
//	        --unshare-all und übergibt die Sandbox-Enden als FD 3 + FD 4.
//	GUEST:  läuft im Sandbox-Netz-Namespace (nur Loopback):
//	          FD 3 = Echo-Kanal      (roher Durchstich)
//	          FD 4 = TCP-Tunnel      (Kanal-E-Muster: Host -> Sandbox-Loopback)
//
// Gezeigt wird:
//
//	Phase 1: Host schreibt in sein Socketpair-Ende → Guest echo't zurück.
//	         => Kommunikation durchquert die Isolation.
//	Phase 2: Host verbindet sich auf 127.0.0.1:18080 (Host-Listener),
//	         der Verkehr wird über FD 4 in die Sandbox getunnelt und dort
//	         mit einem HTTP-Server auf 127.0.0.1:8080 beantwortet.
//	         => Der "innere" Socket ist von außen erreichbar.
//	Negativnachweis: Die Sandbox hat kein externes Netz — Dial-Versuche
//	         nach draußen scheitern, obwohl der Tunnel funktioniert.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	guestHTTPPort    = "8080"  // HTTP-Server IMMER in der Sandbox
	hostForwardPort  = "18080" // Listener AUF DEM HOST (Kanal E)
	guestReadyMarker = "KEG_POC_READY\n"
)

func main() {
	if os.Getenv("KEG_POC_GUEST") == "1" {
		guest()
		return
	}
	host()
}

// ---------------------------------------------------------------- HOST ----

func host() {
	fmt.Println("=== keg PoC: Socketpair-Durchstich durch bwrap ===")

	if _, err := exec.LookPath("bwrap"); err != nil {
		fatal("bwrap nicht gefunden")
	}
	exe, err := os.Executable()
	if err != nil {
		fatal("Executable nicht auflösbar: %v", err)
	}
	exeDir := filepath.Dir(exe)

	// Zwei Socketpairs: [0]=Host-Ende, [1]=Sandbox-Ende (wird FD 3 bzw. 4)
	echoPair := mustSocketpair("echo")
	tunPair := mustSocketpair("tunnel")

	cmd := exec.Command("bwrap",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--ro-bind", exeDir, exeDir, // das eigene Binary erreichbar halten
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--unshare-all", // PID/IPC/NET/UTS/User/Cgroup — volle Isolation
		"--die-with-parent",
		exe,
	)
	cmd.Env = append(os.Environ(), "KEG_POC_GUEST=1")
	cmd.ExtraFiles = []*os.File{echoPair[1], tunPair[1]} // -> FD 3, FD 4
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("[host] starte bwrap --unshare-all ...")
	if err := cmd.Start(); err != nil {
		fatal("bwrap-Start fehlgeschlagen: %v", err)
	}
	echoPair[1].Close() // Kind-Enden im Parent schließen
	tunPair[1].Close()
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	echo := echoPair[0]
	tun := tunPair[0]

	// Auf Bereitschaft des Gastes warten (erste Zeile über den Echo-Kanal)
	reader := bufio.NewReader(echo)
	line, err := reader.ReadString('\n')
	if err != nil || line != guestReadyMarker {
		fatal("Gast nicht bereit (got %q, err=%v)", line, err)
	}
	fmt.Println("[host] Gast gemeldet (über FD-3-Kanal): READY")

	// ---- Phase 1: Echo über den rohen Durchstich ----
	fmt.Println("\n--- Phase 1: Echo über Unix-Socketpair (FD 3) ---")
	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("hallo aus dem host #%d", i)
		start := time.Now()
		if _, err := fmt.Fprintln(echo, msg); err != nil {
			fatal("senden fehlgeschlagen: %v", err)
		}
		reply, err := reader.ReadString('\n')
		if err != nil {
			fatal("kein Echo: %v", err)
		}
		fmt.Printf("[host] gesendet: %-32q empfangen: %-32q (%v)\n",
			msg, trimNL(reply), time.Since(start).Round(time.Microsecond))
	}
	fmt.Println("✓ Durchstich steht: Host <-> Sandbox kommunizieren über FD 3.")

	// ---- Phase 2: TCP-Durchgriff auf den inneren Loopback ----
	fmt.Printf("\n--- Phase 2: Tunnel zu Sandbox-%s (Kanal-E-Muster, FD 4) ---\n", guestHTTPPort)

	ln, err := net.Listen("tcp", "127.0.0.1:"+hostForwardPort)
	if err != nil {
		fatal("Host-Listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			// PoC: eine Verbindung gleichzeitig; produktiv würde hier
			// muxado je Verbindung einen Stream öffnen.
			go pipeThrough(tun, client)
		}
	}()

	url := fmt.Sprintf("http://127.0.0.1:%s/", hostForwardPort)
	fmt.Printf("[host] GET %s ...\n", url)
	resp, err := http.Get(url) //nolint:noctx — PoC
	if err != nil {
		fatal("HTTP durch den Tunnel fehlgeschlagen: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("[host] HTTP %d, Body: %q\n", resp.StatusCode, trimNL(string(body)))
	if resp.StatusCode == 200 && len(body) > 0 {
		fmt.Println("✓ Der innere Sandbox-Socket ist von außen erreicht:")
		fmt.Printf("  Host :%s  --FD4-->  Sandbox 127.0.0.1:%s (HTTP)\n",
			hostForwardPort, guestHTTPPort)
	}

	// ---- Negativnachweis: kein externes Netz in der Sandbox ----
	fmt.Println("\n--- Negativnachweis: externes Netz der Sandbox ---")
	if _, err := fmt.Fprintln(echo, "PROBE_NET"); err != nil {
		fatal("senden fehlgeschlagen: %v", err)
	}
	result, err := reader.ReadString('\n')
	if err != nil {
		fatal("keine Antwort: %v", err)
	}
	fmt.Printf("[host] Gast berichtet: %s", result)

	fmt.Println("\n=== PoC bestanden ===")
}

// pipeThrough verbindet einen Host-TCP-Client 1:1 mit dem Tunnel-FD;
// der Gast dialt seinerseits das Ziel auf seinem Loopback.
func pipeThrough(tun io.ReadWriteCloser, client net.Conn) {
	defer client.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(tun, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, tun); done <- struct{}{} }()
	<-done
}

// ---------------------------------------------------------------- GUEST ---

func guest() {
	echoConn := fileConn(3, "echo")
	tunConn := fileConn(4, "tunnel")

	uid := os.Getuid()
	fmt.Printf("[guest] laufe in der Sandbox (uid=%d). Starte Services ...\n", uid)

	// HTTP-Server auf dem (isolierten) Sandbox-Loopback
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "Hallo vom HTTP-Server INNERHALB der Sandbox (pid %d)\n", os.Getpid())
	})
	ln, err := net.Listen("tcp", "127.0.0.1:"+guestHTTPPort)
	if err != nil {
		guestFatal(err)
	}
	go func() { _ = http.Serve(ln, mux) }()

	// Echo-Server über FD 3 + Ready-Signal an den Host
	go func() {
		r := bufio.NewReader(echoConn)
		if _, err := fmt.Fprint(echoConn, guestReadyMarker); err != nil {
			guestFatal(err)
		}
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch trimNL(line) {
			case "PROBE_NET":
				// Negativprobe: externes Netz muss blockiert sein
				conn, derr := net.DialTimeout("tcp", "1.1.1.1:80", 2*time.Second)
				if derr != nil {
					fmt.Fprintf(echoConn,
						"Dial 1.1.1.1:80 blockiert ✓ (%v) — Isolation aktiv\n", derr)
				} else {
					conn.Close()
					fmt.Fprintln(echoConn, "ACHTUNG: Dial nach draußen ERFOLGREICH — Isolation kompromittiert!")
				}
			default:
				fmt.Fprintf(echoConn, "echo: %s", line) // 1:1 zurück
			}
		}
	}()

	// Tunnel-Server über FD 4: dialt das Ziel auf dem eigenen Loopback.
	// PoC: sequenziell, eine Verbindung nach der anderen.
	for {
		c, err := net.Dial("tcp", "127.0.0.1:"+guestHTTPPort)
		if err != nil {
			guestFatal(err)
		}
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(tunConn, c); done <- struct{}{} }()
		go func() { _, _ = io.Copy(c, tunConn); done <- struct{}{} }()
		<-done
		c.Close()
	}
}

// -------------------------------------------------------------- HELPERS ---

// mustSocketpair erzeugt ein AF_UNIX-SOCK_STREAM-Paar (das pwpeer-Muster).
func mustSocketpair(name string) [2]*os.File {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		fatal("socketpair (%s): %v", name, err)
	}
	a := os.NewFile(uintptr(fds[0]), name+"-host")
	b := os.NewFile(uintptr(fds[1]), name+"-sandbox")
	return [2]*os.File{a, b}
}

func fileConn(fd int, name string) net.Conn {
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		guestFatal(fmt.Errorf("FD %d (%s) nicht vorhanden", fd, name))
	}
	c, err := net.FileConn(f)
	if err != nil {
		guestFatal(err)
	}
	return c
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[host] ✗ "+format+"\n", args...)
	os.Exit(1)
}

func guestFatal(err error) {
	fmt.Fprintf(os.Stderr, "[guest] ✗ %v\n", err)
	os.Exit(1)
}

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
