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

# Host-Umgebungsvariablen durchreichen oder setzen:
bin/keg run -e LANG -e COLORTERM -e CUSTOM_VAR=value -- bash

# Template-Variablen beim Aufruf setzen oder überschreiben:
bin/keg run --var token_ttl=1800 -V custom_greeting=hello -- bash

# Alle Host-Variablen durchreichen (außer gesperrte Credentials/Proxies):
bin/keg run --inherit-all -- bash

# Kombination: Alle Host-Variablen und gezielt gesperrte Variablen durchreichen:
bin/keg run --inherit-all -e AWS_SESSION_TOKEN -e HTTP_PROXY -- bash
```

#### 2. Repository-Freigabe & Trust (`keg trust`)

Nicht-leere `.keg.yaml`-Dateien und zugehörige Trust-Anchors (z. B. `trust_anchors:` oder referenzierte `justfiles` bei delegierten Tasks) unterliegen dem Repository-Trust-Gate:

```bash
# Aktuelle Repository-Konfiguration freigeben / genehmigen:
bin/keg trust

# Freigabe-Status prüfen (TRUSTED, CHANGED, NONE):
bin/keg trust --status

# Freigabe für das Repository widerrufen:
bin/keg trust --revoke
```

#### 3. Layer-Verwaltung (`keg list`, `clean`, `clean-cache`)

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

#### 4. Host-Delegation (`keg delegate`)

Innerhalb der Sandbox können freigegebene Tasks an den Host-Runner delegiert werden:

```bash
# Delegiert 'test-playwright' transparent an den Host:
bin/keg delegate test-playwright login.spec.ts 8080

# Erlaubte Git-Kommandos auf dem Host ausführen:
bin/keg delegate git commit -m "feat: new feature"
```

#### 5. Hintergrund-Daemon (`keg serve`)

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

# Umgebungsvariablen-Steuerung (Deny-by-default)
env:
  inherit:
    - LANG
    - COLORTERM
  set:
    LOG_FORMAT: json

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

# Port-Rückkanal: Host-Verbindungen in die Sandbox durchreichen (§4.9)
#
# Ein Dev-Server läuft IN der Sandbox (z.B. :3000). Damit ihn der Host
# erreicht (Browser, Playwright, curl), deklariert das Repo die Ports.
# keg — Kernel-isolated Execution with Gateways bindet dafür Host-Listener und tunnelt jede Verbindung über
# Kanal E in die Sandbox zum Deklarationsziel.
ports:
  - "3000"              # Sandbox 127.0.0.1:3000 -> Host 127.0.0.1:3000
  - "5432:15432"        # Sandbox :5432 -> abweichender Host-Port 15432
  - name: dev-server
    port: 8080
    dynamic: true       # kollisionsfreier Host-Port, in der Sandbox als
                        # $KEG_PORT_DEV_SERVER erreichbar
```

**So funktioniert das Durchreichen (Host → interner Sandbox-Port):**

1. Der Service läuft **in** der Sandbox und bindet `127.0.0.1:<guest>` —
   von außen unerreichbar, da die Sandbox nur eigenes Loopback besitzt.
2. Bei Bedarf exponiert der Host den Port: Deklarationen ohne Trennpunkt
   (`"3000"`) nutzen denselben Host-Port; `"<guest>:<host>"` wählt einen
   abweichenden Host-Port; `dynamic: true` reserviert kollisionsfrei einen
   freien Host-Port und schreibt ihn als `$KEG_PORT_<NAME>` in die
   Sandbox-Env (Namen normalisiert zu `[A-Z0-9_]`).
3. keg verbindet sich mit jedem Verbindungsaufbau über **Kanal E**
   in die Sandbox; der Guest-Forwarder wählt das Ziel auf dem Sandbox-
   Loopback. Die Sandbox erhält dadurch **keinen** ausgehenden Weg — sie
   kann nur annehmen, was hereingebracht wird.
4. Sicherheit: Host-seitig wird ausschließlich `127.0.0.1` gebunden,
   niemals `0.0.0.0`; Guest-seitig werden nur deklarierte Ziele gedialt
   (Deny-by-default). Details und Invarianten: CONCEPT.md §4.9 und
   THREAT_MODEL.md §5.8.

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

# Host-Quellen für Secrets mit automatischem Refresh (unterstützt Go-Templates: .Vars.instance, .Vars.token_ttl, .Vars.secret_name)
secret_sources:
  ai_secret_key:
    cmd: ["genkey", '{{ .Vars.instance | default "keg" }}', '{{ .Vars.token_ttl | default "60" }}']
    interval: 30s
    timeout: 5s
    on_refresh_error: keep
    # always: true   # optional: Secret in JEDE Sandbox einspielen

# Bestehende Host-Dateien als Secrets bereitstellen (ro-bind nach
# /run/secrets/<name>; ~ und $VAR werden expandiert). Repo deklariert
# den Bedarf per `secrets:` — dieselbe Datei kann so mehreren Sandboxes
# bereitgestellt werden, ohne sie zu kopieren.
secrets:
  github_pat: "~/.config/gh/hosts.yml"

# Per-Ziel-Repo zusätzliche Secret-Bedarfe (ver-einigt mit den `secrets:`-
# Deklarationen der Repo-`.keg.yaml`): Das Repo selbst bleibt unberührt.
repos:
  "/home/code/agent-repo":
    secrets:
      - name: ai_secret_key
        env: AI_SECRET_KEY

# Sicherheits- und LSM-Einstellungen
security:
  landlock: auto # auto | on | off

# Zentrales Audit-Log
log:
  audit_file: "~/.config/keg/audit.log"
```

### Secrets aktivieren (drei Wege)

Wer ein Secret liefert (Mechanismus) und *welches* einlaufen soll (Bedarf)
sind getrennt. Ein in der User-Config definiertes Secret wird erst gemountet
(`/run/secrets/<name>`), wenn eine der folgenden Quellen den Bedarf stellt:

1. **Repo-`.keg.yaml`** (portabel, versioniert):
   ```yaml
   secrets:
     - name: ai_secret_key
       env: AI_SECRET_KEY
   ```
2. **`repos[<match>].secrets` in der User-Config** (nur für dieses Ziel-Repo,
   ohne das Repo anzufassen) — wird mit der Repo-Deklaration vereinigt:
   ```yaml
   repos:
     "/home/code/agent-repo":
       secrets:
         - name: ai_secret_key
           env: AI_SECRET_KEY
   ```
3. **`always: true` in `secret_sources`** (global für **jede** Sandbox):
   ```yaml
   secret_sources:
     ai_secret_key:
       cmd: ["genkey", "keg", "1500"]
       interval: 10m
       always: true        # -> /run/secrets/ai_secret_key in JEDER Sandbox
   ```

Der `name` muss jeweils in `secret_sources` oder in der `secrets:`-Map der
User-Config existieren, sonst harter Fehler vor Start. `env:` setzt zusätzlich
`<ENV> = /run/secrets/<name>`.

---

## 5. Beispiele

- **[`examples/pi-agent`](file:///home/coder/dev/keg/examples/pi-agent/README.md):** Vollständiges Beispiel für einen KI-Agenten mit `golang`-Preset, dynamischer `genkey`-Secret-Generierung nach `/run/secrets/ai_secret_key` und `just test-playwright`-Delegation.
- **[`examples/agy`](file:///home/coder/dev/keg/examples/agy/README.md):** **Projekt-Konfiguration (In-Sandbox):** Ausführung von `agy` in der Sandbox; alle Mounts und Netzwerk-Regeln (`mode: transparent`, DNS-Forwarding, TCP-Endpoints) sind in `.keg.yaml` deklariert.
- **[`examples/agy-user-sandbox`](file:///home/coder/dev/keg/examples/agy-user-sandbox/README.md):** **Nutzer-Konfiguration (In-Sandbox):** Sauberes Repository ohne Google-Endpunkte; der Benutzer schaltet `agy` in seiner `user_config.yaml` (`~/.config/keg/config.yaml`) über additive Mounts und Zero-Trust-Netzwerkregeln frei. `agy` läuft **vollständig isoliert und gesandboxt**.
- **[`examples/agy-user-config`](file:///home/coder/dev/keg/examples/agy-user-config/README.md):** **Nutzer-Konfiguration (Host-Delegation):** Sauberes Repository; `agy` wird vom Host ausgeführt und über Kanal C (`runner.extra_prefixes: ["agy"]`) delegiert.

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

- [`CONCEPT.md`](CONCEPT.md) — Detaillierte Architektur, Datenflüsse und Designentscheidungen.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — Bedrohungsmodell und Sicherheitsinvarianten (§8).
- [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) — Meilensteine M1–M9 und Status.
- [`docs/container-requirements.md`](docs/container-requirements.md) — Mindestanforderungen für den Betrieb in Docker / Podman / Kubernetes.
- [`docs/errors.md`](docs/errors.md) — Fehlerbild-Katalog und Exit-Codes.
