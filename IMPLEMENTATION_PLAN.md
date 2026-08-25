# keg — Kernel-isolated Execution with Gateways — Implementierungsplan

> Operative Ausarbeitung der Meilensteine M1–M9 aus `CONCEPT.md`.
> Sicherheitsinvarianten: `THREAT_MODEL.md` §8 (jede ist regressionsgetestet).
> Arbeitsregeln für Coding-Agents: `AGENTS.md`.

---

## 0. Grundprinzipien

* **TDD strikt:** Keine Produktionszeile ohne vorher roten Test (siehe `AGENTS.md`).
* **Testbare Kerne:** Alles Policy-Relevante (Arg-Builder, Matcher, Templating,
  Protokoll-Framing) wird als **reine Funktion/Goroutine ohne Prozessbezug**
  entworfen — damit ist es unit-testbar. bwrap wird nur in Integrationstests
  echt gestartet.
* **Abhängigkeitsbudget:** siehe §1 — neue Deps nur mit dokumentierter
  Begründung.
* **Jeder WP endet mit:** grünem `make lint test`, aktualisierter Doku,
  Conventional Commit pro abgeschlossenem Task.

---

## 1. Repository-Layout & Abhängigkeitsbudget

```
cmd/keg/            # CLI (urfave/cli), thin wrapper
internal/config/        # .keg.yaml + User-Config laden, mergen, validieren
internal/template/      # eingeschränkte Template-Engine (.Vars/.Env)
internal/orchestrator/  # Socketpairs, FD-Map, bwrap-Argument-Bau, Lifecycle
internal/egress/proxy/  # Kanal A: Whitelist-Proxy + Upstream-CONNECT
internal/egress/dns/    # Kanal B: Embedded DNS + Framing + Bridges
internal/runner/        # Kanal C: Delegations-Daemon + Whitelist-Engine
internal/portsfw/       # Kanal E: Port-Rückkanal
internal/secrets/       # Secret-Bind-Refresher
internal/landlock/      # optionale LSM-Härtung (best effort)
internal/guestagent/    # Sandbox-Entrypoint: Bridges starten, exec/serve
pkg/keg/            # öffentliche Library-API (WP9)
test/integration/       # bwrap-gestützte Integrationstests (Build-Tag)
```

### Direkte Runtime-Abhängigkeiten (Budget — geschlossen!)

| Modul | Zweck | Ersatz durch Stdlib möglich? |
|---|---|---|
| `github.com/urfave/cli/v3` | CLI-Rahmen (Projektvorgabe) | ja, aber Vorgabe |
| `github.com/moby/sys/reexec` | Self-Start in bwrap | nein (bewährt, klein) |
| `golang.ngrok.com/muxado` | Stream-Multiplexing über 1 FD | theoretisch ja; Aufwand zu hoch |
| `gopkg.in/yaml.v3` | Config-Parsing (strict decoding) | nein |
| `github.com/miekg/dns` | DNS-Protokoll | nein (RFC 1035 selbst wäre fehleranfällig) |
| `golang.org/x/sys` | Landlock-Syscalls (nur WP8) | Raw-Syscall möglich; x/sys ist vertretbar |

**Explizit NICHT (v1):** `google.golang.org/grpc`/protobuf (Daemon-API v1 nutzt
dasselbe Length-Prefix-JSON wie der Runner — gRPC erst bei nachgewiesenem
Bedarf als separates Modul), keine HTTP-Frameworks, keine Logging-Frameworks
(`slog` reicht).

### Dev-Tooling

`golangci-lint` (Config: `.golangci.yml`), Go-Race-Detector, `go mod tidy`
muss diff-frei sein.

---

## 2. Phase 0 — Fundament (Vorbereitung von M1)

**Aufgaben**

* [ ] Repo-Skelett nach §1 anlegen, `go.mod` (`go 1.27+`).
* [ ] `.golangci.yml` einchecken; `make lint`, `make test`, `make test-integration`,
      `make build` (Makefile).
* [ ] CI-Pipeline (GitHub Actions): lint → unit (`-race`) → integration
      (nur wenn `bwrap` vorhanden, sonst SKIP-Meldung).
* [ ] `cmd/keg` mit urfave/cli: Subcommands `run` (Default), `list`,
      `clean`, `clean-cache`, `serve` (Stub). Globale Flags `--config`,
      `--user-config`, `--verbose`.

**Tests:** CLI-Smoke-Tests (`cli.NewApp().RunAsSubcommand`-Muster),
`make`-Targets laufen lokal grün.

**DoD:** `make lint test` grün auf leerem Kern; CI grün.

---

## 3. WP-M1 — Skeleton: Isolierte Shell

### 3.1 `internal/config`: Laden & Validieren

* Typen spiegeln das Schema aus CONCEPT.md §5 (`strict decoding`, unbekannte
  Felder = Fehler).
* Reine Merge-Funktion `Merge(base, override) (Config, error)` mit der
  Präzedenz Defaults → User global → repos[match] → Repo-YAML → Env.
* Skalare ersetzen, Listen unionieren, Maps keyweise.

**Tests (vor dem Code schreiben)**

* gültiges Minimal-Config parst; jede unbekannte Feld-Variation ⇒ Fehler mit
  Feldpfad;
* Merge-Tabellentests (Skalar/List/Map je Ebene);
* `repos:`-Matching: exakter realpath schlägt Glob, spezifischster Glob
  gewinnt, kein Treffer ⇒ nur Global;
* `~`/`$VAR`-Expansion inkl. Fehlerfall.

**DoD:** Coverage `internal/config` ≥ 90 %.

### 3.2 `internal/orchestrator`: Arg-Builder (Kernstück)

* `BuildArgs(cfg, paths) []string` — **totale Funktion**, kein I/O:
  Basis-Binds, Symlinks, proc/dev/tmpfs, Overlay-Modi, Ports später,
  `--unshare-all --die-with-parent --disable-userns`, Env-Injection.
* Isolation-schwächende `bwrap_args` werden nur mit
  `Security.AllowWeakBwrap=true` übernommen, sonst Fehler **mit Flag-Namen**.
* FD-Plan als Konstante (`FDProxy=3 …`) — eine Quelle der Wahrheit.

**Tests**

* Goldentests: Config → erwartete Argumentliste (Table-driven, Snapshots in
  `testdata/`);
* schwache Flags ohne Freigabe ⇒ Fehlermeldung enthält exakt das Flag;
* Reihenfolge-Stabilität (deterministische Sortierung der Mounts).

### 3.3 Launch & Guest-Entrypoint

* `syscall.Socketpair`-Helper (mit `/proc/self/fd`-Audit im Debug-Modus:
  vor Start werden offene FDs geloggt — Leaks sichtbar machen).
* reexec-Registrierung; Guest startet (noch) nichts und `exec`s die Shell.
* Env-Hygiene: Host-Proxy-/Cloud-Variablen werden nie vererbt (Liste aus
  CONCEPT.md), nur gesetzte Werte.

**Integrationstests** (Build-Tag `integration`, Skip ohne bwrap)

* `TestSandboxShellIsolated:` Shell in Sandbox, `ip link` zeigt nur `lo`,
  `$HOME` ist tmpfs, Repo rw, `/usr/bin` readonly (write schlägt fehl);
* FD-Erbgut: genau FDs 0–3(+n) offen (via `/proc/self/fd` gezählt).

**DoD:** `keg run -- bash` liefert isolierte Shell; Integrationstest grün.

---

## 4. WP-M2 — Proxy-Kanal (A)

### 4.1 Whitelist-Matcher

* `Match(domain, patterns) Decision` — exakt + `*.suffix` (Single-Level),
  deterministisch, längster Suffix gewinnt.

**Tests:** Tabellenfälle exakt/Wildcard/Subdomain-Fallen (`evil-golang.org`),
leere Whitelist, Wildcard-vs-exakt-Priorität.

### 4.2 CONNECT-Proxy (Host-Seite)

* Request-Parsing (`http.ReadRequest` auf muxado-Stream), 403-Antworten mit
  Begründung, Upstream-CONNECT (`dialViaUpstreamProxy`) mit Statusprüfung,
  vollduplexes Copy mit beidseitigem Timeout-Cleanup.
* Audit-Log: `ERLAUBT/BLOCKIERT <host>` — niemals Payload.

**Tests:** Protokolltests über `net.Pipe()` (echte bwrap-frei):
CONNECT erlaubt/verboten, Upstream verweigert CONNECT ⇒ 502,
Plain-HTTP-Pfad, halboffene Verbindungen leaken keine Goroutinen
(goroutine-leak-check).

### 4.3 Guest-Bridge + Env-Injection

* Bridge lauscht `127.0.0.1:8080`; `HTTP(S)_PROXY`/`NO_PROXY` werden gesetzt.

**Integrationstest:** `go run mvdan.cc/sh@…`? Nein — stdlib: Sandbox-Client
nutzt `http.Get("https://proxy.golang.org/")` gegen einen lokalen
Fake-Upstream (Host-Seite), Whitelist entscheidet; zweiter Fall blockiert.

**DoD:** `keg run -- curl https://proxy.golang.org` funktioniert whitelisted,
unbekannte Domain ⇒ sichtbare 403.

---

## 5. WP-M3 — DNS-Kanal (B)

* Framing-Codec: `ReadFrame/WriteFrame` (2-Byte-Length-Prefix, RFC 1035 §4.2.2)
  als eigenes Paket — auch vom Runner wiederverwendbar.
* Resolver-Logik: hosts (exakt vor Wildcard, Single-Level-Splat) → Whitelist →
  Upstream (`miekg/dns` Client) → NXDOMAIN. `on_refresh_error` gibt es hier
  nicht; Timeouts konfigurierbar.
* Bridges: UDP *und* TCP Listener `127.0.0.1:53`; Queue statt Drop
  (Backpressure-Hinweis §4.4); resolv.conf-Injektion.

**Tests:** Codec-Roundtrip + Truncation; Resolver-Tabellentests (hosts,
Wildcard-Tiefe `a.b.foo.tld` matcht nicht, Whitelist-Fehlschlag ⇒ NXDOMAIN);
UDP-Bridge-Lasttest (100 parallele Queries, keine Drops, goroutine-leak-frei).

**Integrationstest:** `getent hosts proxy.golang.org` in der Sandbox auflöst
(Fake-Upstream auf Host), unbekannte Domain ⇒ NXDOMAIN.

**DoD:** DNS-Queries laufen ausschließlich über Kanal B; Audit-Zeilen sichtbar.

---

## 6. WP-M4 — Templates, Vars, Env, Ports

### 6.1 Template-Engine (`internal/template`)

* Kontext **nur** `.Vars`, `.Env`; Funktionen: `default`; sonst harter Fehler.
* `Vars`-Merge: Repo → User global → repos[match] → `KEG_VAR_*`.
* Anwendungsfelder: mounts src/dest, dns.hosts-Werte, env.set, ports-Namen.

**Tests:** jede nicht-template-bare Struktur bleibt literal (Delegations-
Regeln können nicht umgeleitet werden); fehlende Var ohne `default` ⇒ Fehler
mit Zeilenreferenz; `allow_env=false` ⇒ `.Env`-Zugriff = Konfigurationsfehler.

### 6.2 First-class `env` & `bwrap_args`

* unset-vor-set Semantik; Werte template-bar; Weak-Flag-Gate (aus 3.2).

### 6.3 Sprach-Templates (builtin)

* go/java/node/python als Datenstrukturen; Cache-Quellen-Erkennung
  (`go env GOMODCACHE` etc.) mit Fallbacks; GOROOT-Mapping.

**Integrationstest:** `keg run -- go build ./...` im Testrepo läuft offline
aus Warm-Cache (Cache-Verzeichnisse als Fixtures).

### 6.4 Port-Rückkanal (Kanal E)

* Parser für `"3000"`, `"src:dst"`, `{name, port, dynamic}`; Host-Bind
  **ausschließlich** `127.0.0.1`; `dynamic` vergibt freien Port und exportiert
  `KEG_PORT_<name>`.

**Tests:** Parser-Tabellentests; Bind-Verweigerung bei Nicht-Loopback;
Dynamic-Allocation setzt Env korrekt.

**DoD:** Playwright-artiger Workflow: Dev-Server in der Sandbox, Host-curl auf
`127.0.0.1:<port>` antwortet (Integrationstest).

---

## 7. WP-M5 — Delegation (Kanal C)

### 7.1 Whitelist-Engine

* Klassen exact/prefix/raw; Raw-Matcher als totale Funktion
  `MatchRaw(argv, Rule) Decision` mit den 5 Schritten aus CONCEPT.md §4.5
  (inkl. `forbidden_args_matching` — Glob **und** Regex).
* Merge mit User-Overrides (`extra_*`, Vereinigungsmenge).

**Tests (umfangreichste Suite des Projekts)**

* Git-Fälle aus dem Bestand: globale Optionen mit Wert/Flag/`--opt=value`;
  Subcommand erkannt/nicht erkannt; `git push` ⇒ deny;
* URL-Blocker: `git fetch https://…`, `git@…`, `ssh://…` ⇒ deny;
* Regex- und Glob-Semantik; leere `subcommands` ⇒ Konfigurationsfehler;
* Prefix-Klasse greift nicht bei Verwechslung
  (`test-playwrightx` ≠ `test-playwright`).

### 7.2 Runner-Server

* Length-Prefix-JSON + b64-Argumentframing; Live-Streaming stdout/stderr;
  Exit-Code-Marker; Pfad-Jail (`filepath.Rel`-Prüfung gegen Repo-Root);
  **Git-Hook-Unterdrückung** für delegierte Git-Jobs
  (`-c core.hooksPath=<leeres Dir>` — THREAT_MODEL §5.4);
* Signal-Handler killt Jobs bei Sandbox-Exit; `RUNNER_WHITELIST`-Kompat.

**Integrationstest:** `just delegate container-build`-Ersatz: Fake-Job
schreibt Marker + Exit-Code; Ablehnung ⇒ 126 mit Grund; mehrzeilige
Commit-Messages via b64.

**DoD:** `sandbox.just`-Muster funktioniert unverändert (`CODE_SANDBOX`).

---

## 8. WP-M6 — Overlays & Layer-Management

* Modi ephemeral/disk-overlay/isolated-cache-name in den Arg-Builder integrieren
  (Goldentests erweitern); UID-kompatibles `mkdirAll` für Upper/Workdirs.
* Management-Kommandos `--list/--clean/--clean-cache/--clean-all` mit
  Stufenlöschung (chmod → unshare-mount → sudo, letzteres interaktiv).

**Tests:** Overlay-Args in Goldens; Layer-Lifecycle-Integrationstest
(erstellen → sichtbar → clean → weg); `--ephemeral` lässt `git status`
jungfräulich.

**DoD:** Alle vier Overlay-Flags verhalten sich wie im Bestand dokumentiert.

---

## 9. WP-M7 — Polish

* `log/slog`-strukturiertes Logging; Audit-Datei optional (User-Config).
* Parallel-Instanzen (`--name`, deterministische Pfade).
* Fehlerbild-Katalog als `docs/errors.md` (Texte = Testexpectations).
* Race-Detector sauber; goroutine-leak-check in allen Server-Tests.

---

## 10. WP-M8 — Hardening

* **Secrets:** `secret_sources` (User-Config), Initial-Fetch vor Start,
  Refresher-Goroutinen mit `interval`, atomarer Swap (Temp+rename im selben
  Dir), Directory-Bind `/run/secrets`, `on_refresh_error: keep|fail`,
  Mode 0400/0700, Cleanup bei Close, Audit nur `(changed|unchanged|error)`.

  **Tests:** Atomarität (Concurrent-Reader sehen nie Halbfabrikate), Refresh-
  Fehler hält letzten guten Wert, Cleanup entfernt Reste, Repo referenziert
  unbekannten Namen ⇒ Validierungsfehler.
* **Landlock** (`internal/landlock`): Ruleset aus effektiven Schreibzielen;
  Feature-Detection; `auto|on|off`. Tests: Kernel-Support-Erkennung gemockt;
  on-ohne-Support ⇒ Warnung (auto) bzw. Fehler (on).
* **`forbidden_args_matching`** falls nicht schon in WP-M5 erledigt.
* **CGO-Check:** Erreichbarkeit von `as`/`ld` prüfen, klare Fehlermeldung.
* **FD-Leak-Audit:** vor Launch `/proc/self/fd` zählen; > erwartete Map ⇒
  Warnung/Fehler (THREAT_MODEL §5.1).

---

## 11. WP-M9 — Go-API & Daemon

* Refactor: Orchestrator-Kern hinter Schnittstelle; `pkg/keg`:
  `Launch(opts…)`, `(*Sandbox).Command/Output/SecretPath/Close`, Options-
  Pattern; Kontext-Abbruch = Sandbox-Down.
* **Guest-Agent (Kanal D):** Entrypoint bleibt resident; Exec-Requests
  (spawn/stdin/stdout/stderr-events/signal/exit) über eigene muxado-Session;
  CLI-Modus verhält sich unverändert (exec transparent).
* **Daemon:** `keg serve` mit Unix-Socket (Default, `SO_PEERCRED`-Audit)
  und TCP-Loopback-Opt-in; Token-Pflicht bei Netz-Bind, sonst Startverweigerung;
  Limits paralleler Sandboxen; v1-Protokoll = Length-Prefix-JSON (**kein
  gRPC** — Budget §1; Upgrade-Pfad offen).
* Library-API-Tests: Launch/Exec/Close-Lifecycle, Kontext-Abbruch räumt auf,
  Policy-Identität zwischen API- und CLI-Pfad (gleiche Engine-Instanz).

---

## 12. Teststrategie (projektweit)

| Ebene | Was | Wo |
|---|---|---|
| Unit (Standard) | alle reinen Funktionen: Matcher, Arg-Builder, Templating, Framing, Merge | neben dem Code |
| Protokoll-Unit | Server/Sockets via `net.Pipe()`, goroutine-leak-check | neben dem Code |
| Integration (Tag `integration`) | echte bwrap-Läufe, Offline-Workflows, Playwright-Port-Flow | `test/integration/` |
| Golden | bwrap-Args, Fehlermeldungen | `testdata/` |

Regeln: `-race` immer; Skip ohne bwrap mit sichtbarer Meldung (nie stumm);
Fehlertexte sind Teil der API (Golden-getestet); Security-Invarianten aus
THREAT_MODEL §8 haben jeweils ≥ 1 benannten Test
(`TestInvariant_NoNetExceptChannels`, `TestInvariant_WeakBwrapNeedsConsent`, …).

---

## 13. Reihenfolge & Schnitte

```
Phase0 → M1 → M2 → M3 ┐
                      ├→ M4 → M5 → M6 → M7 → M8 → M9
        (M2/M3 parallelisierbar, getrennte Pakete)
```

Erster nutzbarer Schnitt nach **M3**: offline-fähige Go-Sandbox mit
kontrolliertem Egress. Nach **M5** vollständig für den Bestands-Workflow
nutzbar. Jeder WP ist unabhängig merge-bar; Breaking Changes an der Config
nur bis M4 (danach Versionierung `version: "1"` ernst nehmen).
