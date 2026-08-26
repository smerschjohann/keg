# keg — Kernel-isolated Execution with Gateways

Isolierte Entwicklungs-Sandbox auf Basis von **bubblewrap** (`bwrap`) mit Zero-Trust Egress — ein einzelnes, robustes Go-Binary statt fehleranfälliger Shell-Skripte.

---

## 1. Überblick & Architektur

`keg` schirmt ungetesteten oder durch KI-Agenten generierten Code in einer hermetischen Sandbox ab. Die Isolation erfolgt auf Kernel-Ebene über unprivilegierte Namespaces (`--unshare-all`) und optional über **Landlock LSM**-Dateisystemrestriktionen.

### Kommunikationskanäle (FD-Map & Zero-Trust)

Jegliche Kommunikation zwischen Sandbox und Host läuft ausschließlich über kontrollierte Filedeskriptoren:

```
┌───────────────────────────── HOST ─────────────────────────────┐
│ keg (Host-Orchestrator)                                    │
│  ├─► Kanal A (FD 3): Egress HTTP/HTTPS-Proxy (CONNECT-Whitelist) │
│  ├─► Kanal B (FD 4): Whitelist-DNS (:53, loopback resolv.conf) │
│  ├─► Kanal C (FD 5): Host-Delegation-Runner (Whitelist-Tasks)  │
│  ├─► Kanal D (FD 6): Control / Guest-Agent (RPC & Streaming)   │
│  ├─► Kanal E (FD 7): Reverse-Port-Forwarding (KEG_PORT_*)  │
│  └─► /run/secrets:   Dynamische Secrets (0400 ro-bind, Refresh)│
└──────────────────────────────┬─────────────────────────────────┘
                               │ bwrap socketpairs
┌──────────────────────────────▼─────────────────────────────────┐
│ SANDBOX (PID / IPC / Net / User / Mount / UTS Namespaces)      │
│  ├─► Workload / Agent / Compiler                               │
│  ├─► Loopback Interface (kein Default-Gateway, kein Raw-Netz)  │
│  └─► Landlock LSM (Syscall-Schutz für Rootfs & Mounts)         │
└────────────────────────────────────────────────────────────────┘
```

| Kanal | FD | Protokoll | Funktion |
|---|---|---|---|
| **Kanal A (Proxy)** | `FD 3` | `muxado` Session | HTTP/HTTPS-Proxy mit strikter SNI- und Domain-Whitelist. |
| **Kanal B (DNS)** | `FD 4` | RFC 1035 TCP-Framing | Filternder DNS-Server auf Loopback `:53`, statische Hosts & Wildcards. |
| **Kanal C (Delegation)** | `FD 5` | Length-Prefixed JSON | Sichere Ausführung freigegebener Host-Tasks (`just delegate`). |
| **Kanal D (Control)** | `FD 6` | `muxado` Session | Control-Kanal & RPC für Library- / Daemon-Modus. |
| **Kanal E (Ports)** | `FD 7` | `muxado` Session | Port-Rückkanal vom Host in die Sandbox (`KEG_PORT_<NAME>`). |

---

## 2. Installation & CLI-Nutzung

### Bauen

```bash
make build          # -> bin/keg
```

### Befehle

#### 1. Sandbox starten (`keg run`)

```bash
# Interaktive Shell im aktuellen Repository:
bin/keg run

# Befehl direkt isoliert ausführen:
bin/keg run -- go test ./...

# Werfbarer Lauf (Repo bleibt durch tmpfs-Upper unverändert):
bin/keg run --ephemeral -- just build

# Persistenter Disk-Overlay (Änderungen überleben Sandbox-Exit):
bin/keg run --disk-overlay agent-feature -- bash

# Cache-Isolation für Go-/Toolchain-Caches (Warm-Cache lesend, tmpfs schreibend):
bin/keg run --isolate-caches -- go build ./...

# Parallele Sandbox-Instanzen mit deterministischem Namen:
bin/keg run --name worker-1 -- just test
```

#### 2. Layer-Verwaltung (`keg list`, `clean`, `clean-cache`)

```bash
# Alle persistenten Disk- und Cache-Layer auflisten:
bin/keg list

# Spezifischen Repo-Layer löschen:
bin/keg clean agent-feature

# Spezifischen Cache-Layer löschen:
bin/keg clean-cache agent-feature

# Alle Layer mit Sicherheitsrückfrage bereinigen:
bin/keg clean --all
```

#### 3. Host-Delegation (`keg delegate`)

Innerhalb der Sandbox können freigegebene Tasks an den Host-Runner delegiert werden:

```bash
# Delegiert 'test-playwright' transparent an den Host:
bin/keg delegate test-playwright login.spec.ts 8080

# Erlaubte Git-Kommandos auf dem Host ausführen:
bin/keg delegate git commit -m "feat: new feature"
```

#### 4. Hintergrund-Daemon (`keg serve`)

Startet den RPC-Daemon für Daemon- und Remote-Steuerung:

```bash
# Standard Unix-Socket (0660, SO_PEERCRED-Audit):
bin/keg serve --listen unix:///run/keg/api.sock

# TCP-Listener (erfordert zwingend Authentifizierungs-Token):
bin/keg serve --listen 127.0.0.1:7777 --auth token --token "mein-geheimes-token"
```

---

## 3. Go-Library-API (`pkg/keg`)

`keg` kann direkt als Go-Bibliothek eingebunden werden:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/smerschjohann/keg/pkg/keg"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sb, err := keg.Launch(ctx, "/pfad/zum/repo",
		keg.WithEphemeral(),
		keg.WithName("agent-task"),
		keg.WithCommand("go", "test", "./..."),
	)
	if err != nil {
		log.Fatalf("Launch: %v", err)
	}
	defer sb.Close()

	// Pfad zu dynamischen Secrets in der Sandbox abfragen
	secretPath := sb.SecretPath("ai_secret_key") // -> "/run/secrets/ai_secret_key"
	fmt.Printf("Secret gemountet unter: %s (Host-PID: %d)\n", secretPath, sb.Pid())

	// Auf Beendigung warten
	exitCode, err := sb.Wait()
	if err != nil {
		log.Fatalf("Wait: %v", err)
	}
	fmt.Printf("Sandbox beendet mit Exit-Code: %d\n", exitCode)
}
```

---

## 4. Konfiguration

### Repository-Konfiguration (`.keg.yaml`)

Liegt im Root-Verzeichnis des Repositories:

```yaml
version: "1"

# Vordefinierte Toolchain-Presets (golang, rust, python, node)
templates:
  - golang

# Dynamische Secrets (0400 read-only unter /run/secrets/<name>)
secrets:
  - name: ai_secret_key
    env: AI_SECRET_KEY

# Netzwerk- und Egress-Richtlinien
network:
  mode: proxy
  dns:
    enabled: true
    hosts:
      db.internal: 10.0.0.5
  sni_domains:
    - api.anthropic.com
    - api.openai.com
    - proxy.golang.org

# Port-Rückkanal (Host -> Sandbox)
ports:
  - name: web
    port: 8080

# Whitelist für Host-Delegation
delegated_tasks:
  exact:
    - build
    - test
  prefixes:
    - "test-playwright"
  raw:
    - cmd: git
      subcommands: [status, diff, log, add, commit]
```

### Benutzer-Konfiguration (`~/.config/keg/config.yaml`)

Maschinen- und benutzerspezifische Einstellungen:

```yaml
paths:
  storage_base: "/var/lib/containers/storage/sandbox"
  tmp_base: "/tmp"

# Host-Quellen für Secrets mit automatischem Refresh
secret_sources:
  ai_secret_key:
    cmd: ["genkey", "my-instance", "60"]
    interval: 30s
    timeout: 5s
    on_refresh_error: keep

# Sicherheits- und LSM-Einstellungen
security:
  landlock: auto # auto | on | off

# Zentrales Audit-Log
log:
  audit_file: "~/.config/keg/audit.log"
```

---

## 5. Beispiele

- **[`examples/pi-agent`](file:///home/coder/dev/keg/examples/pi-agent/README.md):** Vollständiges Beispiel für einen KI-Agenten mit `golang`-Preset, dynamischer `genkey`-Secret-Generierung nach `/run/secrets/ai_secret_key` und `just test-playwright`-Delegation.
- **[`examples/agy`](file:///home/coder/dev/keg/examples/agy/README.md):** Ausführung von Google Antigravity (`agy`) in einer Zero-Trust-Sandbox mit `mode: transparent`, DNS-Forwarding (`8.8.8.8:53`) für `*.googleapis.com` und direktem Zugriff auf `daily-cloudcode-pa.googleapis.com` (ohne HTTP-Proxy).

---

## 6. Entwicklung & Testen

```bash
make lint            # golangci-lint (muss 100% warnungsfrei sein)
make test            # Alle Unit-Tests mit -race
make integration     # bwrap-Integrationstests (Tag: integration)
make tidy            # go mod tidy (muss diff-frei bleiben)
```

---

## 7. Dokumentation

- [`CONCEPT.md`](file:///home/coder/dev/keg/CONCEPT.md) — Detaillierte Architektur, Datenflüsse und Designentscheidungen.
- [`THREAT_MODEL.md`](file:///home/coder/dev/keg/THREAT_MODEL.md) — Bedrohungsmodell und Sicherheitsinvarianten (§8).
- [`IMPLEMENTATION_PLAN.md`](file:///home/coder/dev/keg/IMPLEMENTATION_PLAN.md) — Meilensteine M1–M9 und Status.
- [`docs/errors.md`](file:///home/coder/dev/keg/docs/errors.md) — Fehlerbild-Katalog und Exit-Codes.
