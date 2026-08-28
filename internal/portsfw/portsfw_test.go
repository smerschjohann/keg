package portsfw

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/smerschjohann/keg/internal/config"
)

// fakeListener is a minimal net.Listener stub so the pure resolution core
// stays free of real socket I/O in tests.
type fakeListener struct {
	port int
}

func (f fakeListener) Accept() (net.Conn, error) { return nil, errors.New("not implemented") }
func (f fakeListener) Close() error              { return nil }
func (f fakeListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: f.port} }

func TestResolve(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		specs   []config.PortSpec
		alloc   func(int) (*net.Listener, error)
		want    []ResolvedPort
		wantErr bool
	}{
		{
			name:  "empty specs resolve to nothing",
			specs: nil,
			want:  nil,
		},
		{
			name: "static single port keeps guest=host",
			specs: []config.PortSpec{
				{Guest: 3000, Host: 3000},
			},
			want: []ResolvedPort{{Name: "", HostIP: "127.0.0.1", Guest: 3000, HostPort: 3000}},
		},
		{
			name: "src:dst form maps sandbox port to distinct host port",
			specs: []config.PortSpec{
				{Guest: 5432, Host: 15432},
			},
			want: []ResolvedPort{{Name: "", HostIP: "127.0.0.1", Guest: 5432, HostPort: 15432}},
		},
		{
			name: "named mapping form carries the name",
			specs: []config.PortSpec{
				{Name: "dev-server", Guest: 8080, Host: 8080},
			},
			want: []ResolvedPort{{Name: "dev-server", HostIP: "127.0.0.1", Guest: 8080, HostPort: 8080}},
		},
		{
			name: "custom host ip is preserved",
			specs: []config.PortSpec{
				{HostIP: "0.0.0.0", Guest: 80, Host: 8080},
			},
			want: []ResolvedPort{{Name: "", HostIP: "0.0.0.0", Guest: 80, HostPort: 8080}},
		},
		{
			name: "dynamic specs are allocated in declaration order",
			specs: []config.PortSpec{
				{Guest: 3000, Host: 3000},
				{Name: "dev-server", HostIP: "0.0.0.0", Guest: 8080, Dynamic: true},
				{Name: "second", Guest: 9090, Dynamic: true},
			},
			alloc: func(call int) (*net.Listener, error) {
				ports := []int{44111, 44222}
				ln := fakeListener{port: ports[call]}
				return ptrListener(ln), nil
			},
			want: []ResolvedPort{
				{Name: "", HostIP: "127.0.0.1", Guest: 3000, HostPort: 3000},
				{Name: "dev-server", HostIP: "0.0.0.0", Guest: 8080, HostPort: 44111},
				{Name: "second", HostIP: "127.0.0.1", Guest: 9090, HostPort: 44222},
			},
		},
		{
			name: "allocator failure aborts with wrapped error",
			specs: []config.PortSpec{
				{Name: "dev-server", Guest: 8080, Dynamic: true},
			},
			alloc: func(int) (*net.Listener, error) {
				return nil, errors.New("no ports left")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			call := 0
			got, err := Resolve(tt.specs, func(hostIP string) (*net.Listener, error) {
				if tt.alloc == nil {
					t.Fatal("allocator called for non-dynamic spec")
					return nil, nil
				}
				ln, err := tt.alloc(call)
				call++
				return ln, err
			})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Resolve() = %v, want error", got)
				}
				if !strings.Contains(err.Error(), "no ports left") {
					t.Errorf("error should wrap allocator failure, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Resolve() = %d entries, want %d (%+v)", len(got), len(tt.want), got)
			}
			for i := range tt.want {
				w, g := tt.want[i], got[i]
				if w.Name != g.Name || w.Guest != g.Guest || w.HostPort != g.HostPort {
					t.Errorf("entry[%d] = %+v, want %+v", i, g, w)
				}
			}
		})
	}
}

func ptrListener(l net.Listener) *net.Listener { return &l }

func TestPortEnv_NamedPortsAreExported(t *testing.T) {
	t.Parallel()
	ports := []ResolvedPort{
		{Name: "", Guest: 3000, HostPort: 3000}, // unnamed: no env var
		{Name: "dev-server", Guest: 8080, HostPort: 44111},
		{Name: "db", Guest: 5432, HostPort: 15432},
	}
	env := PortEnv(ports)
	if _, ok := env["KEG_PORT_DEV_SERVER"]; !ok {
		t.Errorf("missing KEG_PORT_DEV_SERVER in %v", env)
	}
	if got := env["KEG_PORT_DEV_SERVER"]; got != "44111" {
		t.Errorf("KEG_PORT_DEV_SERVER = %q, want \"44111\"", got)
	}
	if got := env["KEG_PORT_DB"]; got != "15432" {
		t.Errorf("KEG_PORT_DB = %q, want \"15432\"", got)
	}
	if len(env) != 2 {
		t.Errorf("unnamed port must not be exported: %v", env)
	}
}

func TestPortEnv_SanitizesNamesForShellUse(t *testing.T) {
	t.Parallel()
	// A dash in the name would be unreferenceable in shells
	// ($KEG_PORT_dev-server parses as subtraction).
	env := PortEnv([]ResolvedPort{{Name: "my.port-1", Guest: 1, HostPort: 2}})
	if got, ok := env["KEG_PORT_MY_PORT_1"]; !ok || got != "2" {
		t.Errorf("sanitized env = %v, want KEG_PORT_MY_PORT_1=2", env)
	}
}

func TestTargetHeader_RoundTripAndBounds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{name: "valid port", port: 3000},
		{name: "min port", port: 1},
		{name: "max port fits uint16", port: 65535},
		{name: "zero rejected", port: 0, wantErr: true},
		{name: "overflow rejected", port: 65536, wantErr: true},
		{name: "negative rejected", port: -1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf [2]byte
			err := EncodeTarget(buf[:], tt.port)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("EncodeTarget(%d) = nil, want error", tt.port)
				}
				if _, derr := DecodeTarget(strings.NewReader(string(buf[:]))); derr == nil {
					t.Errorf("DecodeTarget of zeroed buffer must fail")
				}
				return
			}
			if err != nil {
				t.Fatalf("EncodeTarget(%d): %v", tt.port, err)
			}
			got, err := DecodeTarget(newSliceReader(buf[:]))
			if err != nil {
				t.Fatalf("DecodeTarget: %v", err)
			}
			if got != tt.port {
				t.Errorf("roundtrip = %d, want %d", got, tt.port)
			}
		})
	}
}

func newSliceReader(b []byte) *strings.Reader { return strings.NewReader(string(b)) }

func TestParseAllowed_RejectsGarbage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		marker  string
		want    map[int]bool
		wantErr bool
	}{
		{name: "empty marker means none", marker: "", want: map[int]bool{}},
		{name: "single port", marker: "3000", want: map[int]bool{3000: true}},
		{name: "list", marker: "3000,5432,8080", want: map[int]bool{3000: true, 5432: true, 8080: true}},
		{name: "garbage fails closed", marker: "3000,abc", wantErr: true},
		{name: "range fails closed", marker: "3000-3010", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseAllowed(tt.marker)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseAllowed(%q) = %v, want error", tt.marker, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAllowed(%q): %v", tt.marker, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseAllowed(%q) = %v, want %v", tt.marker, got, tt.want)
			}
			for p := range tt.want {
				if !got[p] {
					t.Errorf("port %d missing in %v", p, got)
				}
			}
		})
	}
}
