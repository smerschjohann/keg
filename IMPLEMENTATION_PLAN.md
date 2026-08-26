# keg — Kernel-isolated Execution with Gateways — Implementierungsplan

> Operative Ausarbeitung der Meilensteine M1–M9 aus `CONCEPT.md`.
> Sicherheitsinvarianten: `THREAT_MODEL.md` §8 (jede ist regressionsgetestet).
> Arbeitsregeln für Coding-Agents: `AGENTS.md`.
>
> **Status-Tracker:** Jeder WP-Kopf trägt seinen Umsetzungsstand.
> Stand: **Phase 0 + WP-M1 + WP-M2 vollständig erledigt**, Details in den
> jeweiligen Abschnitten. Abweichungen vom Originalplan sind als
> *Umsetzungsnotiz* dokumentiert (warum/wie wurde abgewichen).

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

**Status:** ✅ erledigt.

**Aufgaben**

* [x] Repo-Skelett nach §1 anlegen, `go.mod` (`go 1.25+`; 1.27 existiert
      noch nicht stabil — bewusste Anpassung).
* [x] `.golangci.yml` einchecken; `make lint`, `make test`, `make integration`,
      `make build` (Makefile; Target heißt `integration`, nicht
      `test-integration`).
* [x] CI-Pipeline (`.github/workflows/ci.yml`): lint → unit (`-race`) →
      integration mit installiertem bubblewrap; Skip-Logik liegt in den Tests.
* [x] `cmd/keg` mit urfave/cli: Subcommands `run` (Default), `list`,
      `clean`, `clean-cache`, `serve` (Stub). Globale Flags `--config`,
      `--user-config`, `--verbose`; zusätzlich `run`-Flags `--repo`,
      `--ephemeral`, `--disk-overlay NAME`.

**Tests:** CLI-Smoke-Tests (In-Process über exportierte `NewCommand()`-
Fabrik), `make`-Targets laufen lokal grün.

**DoD:** ✅ `make lint test` grün; CI-Workflow eingecheckt (Remote-Lauf
folgt mit erstem Push auf GitHub).

---

## 3. WP-M1 — Skeleton: Isolierte Shell

**Status:** ✅ erledigt (inkl. Integrationstests gegen echtes bwrap 0.11).
Siehe *Umsetzungsnotizen* am Ende des Abschnitts — dort liegen mehrere
wichtige, empirisch verifizierte Abweichungen vom Originalplan.

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

**DoD:** Coverage `internal/config` ≥ 90 % (erreicht für die umgesetzten
Pfade; Template-Auflösung folgt in WP-M4 und erweitert die Suite).

**Umgesetzt:** Typen spiegeln CONCEPT.md §5; `ParseRepo`/`ParseUser`
(strict, unbekannte Felder = Fehler mit Feldpfad); `MergeUsers` (Skalar
ersetzen / Listen unionieren / Maps keyweise); `MatchRepo` (exakter
realpath schlägt Glob, längster wörtlicher Präfix gewinnt; Patterns
werden vor dem Matching expandiert); `MergeVars` inkl.
`KEG_VAR_*`-Env-Injektion; `ExpandPath` für `~`/`$VAR` mit hartem
Fehler bei unset Variablen.

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

**Umgesetzt:** Alles oben; Goldens inline im Table-Test statt
`testdata/`-Snapshots (Übersichtlichkeit; bei Bedarf später externalisieren).
Abweichend vom ersten Entwurf: echte `/bin`/`/lib`-ro-Binds statt
Symlinks (merged-/usr-sicher, Layout aus dem Bestand), `-try`-Binds für
optionale CA-Pfade, `/etc/passwd`, `--chdir` ins Repo sowie gesetzte
`PATH`/`SHELL`.

### 3.3 Launch & Guest-Entrypoint

* `syscall.Socketpair`-Helper (mit `/proc/self/fd`-Audit im Debug-Modus:
  vor Start werden offene FDs geloggt — Leaks sichtbar machen).
* reexec-Registrierung; Guest startet (noch) nichts und `exec`s die Shell.
* Env-Hygiene: Host-Proxy-/Cloud-Variablen werden nie vererbt (Liste aus
  CONCEPT.md), nur gesetzte Werte.

**Integrationstests** (Build-Tag `integration`, Skip ohne bwrap — sichtbar
mit Grund, nie stumm)

* [x] `TestSandboxShellIsolated:` Shell in Sandbox, `ip link` zeigt nur
      `lo`, `$HOME` ist tmpfs und beschreibbar, Repo rw, `/usr` readonly
      (write schlägt fehl), `env.set` wird angewendet;
* [x] `TestSandboxFDInheritance:` fds 0–2 Standard + 3–5 als
      Socketpair-Enden (`readlink /proc/self/fd/N` → `socket:[...]`);
* [x] `TestSandboxEphemeralOverlay:` Schreiben in der Sandbox hinterlässt
      nichts im Host-Repo;
* [x] `TestSandboxDiskOverlay:` Zwei Läufe auf demselben Layer — Lauf 1
      schreibt, Lauf 2 liest zurück; Host-Repo bleibt sauber;
* [x] `TestSandboxHostEnvStripped:` Host-Credentials erreichen den
      Sandbox-Prozess nicht.

**DoD:** ✅ `keg run -- <cmd>` liefert isolierte Shell; alle
Integrationstests grün (Suite mehrfach hintereinander stabil).

#### Umsetzungsnotizen M1 (empirisch gegen bwrap 0.11 verifiziert)

Diese Punkte haben den Originalplan korrigiert bzw. präzisiert:

1. **FD-Erbgut:** bwrap hat **kein** `--preserve-fds`. `cmd.ExtraFiles`
   werden unverändert ab fd 3 durchgereicht; der Integrationstest pinnt
   die Socketpair-Enden an fd 3/4/5 (CONCEPT §9).
2. **UserNS:** `--disable-userns` verlangt ein explizites `--unshare-user`,
   obwohl `--unshare-all` es impliziert.
3. **Overlay-Syntax:** `--tmp-overlay`/`--overlay` brauchen mindestens
   einen vorangestellten `--overlay-src`; persistente Layer nutzen
   `--overlay-src LOWER --overlay RW WORK DEST` wie im Bestand. Upper-/Work-Dirs
   gehören auf echte Disk (`/var/lib/containers/storage/sandbox`, ext4) —
   tmpfs-Uppers werden im User-Mode verweigert.
4. **Persistenz:** Writes sind unmittelbar nach dem Sandbox-Exit dauerhaft
   im Upperdir (gemessen, kein verzögertes Flushen). Sichtbarkeitsmodell
   bleibt „nicht gebunden = nicht vorhanden“; ein zwischenzeitlich
   erprobtes `--ro-bind / /` wurde wieder entfernt (zu weitreichende
   ro-Sicht auf den Host).
5. **EBUSY bei Layer-Wiedernutzung:** OverlayFS schützt Upper-/Work-Dirs
   exklusiv pro Superblock (dmesg: „upperdir is in-use as upperdir/workdir
   of another mount“). Remounts direkt nach einem Exit schlagen deshalb
   transient fehl. `Launch()` überwacht daher die Setup-Phase: stirbt
   bwrap vor Command-Start mit der stderr-Signatur „Can't make overlay
   mount“ + „Device or resource busy“, wird bis zu 10× im Abstand von
   500 ms neu gestartet. Jedes andere Ergebnis (inkl. schnell
   fehlschlagender Workloads mit Code 1) wird unverändert über `Wait()`
   durchgereicht — Code 1 allein ist nicht unterscheidbar, nur das
   stderr-Muster.
6. **Env-Hygiene doppelt:** bwrap `--unsetenv` (Liste
   `HostDeniedEnvVars`) plus zweites Strippen im Guest-Entrypoint
   (Defense-in-Depth, je ein Invariantentest).
7. **Früh fertig Commands:** Ein Workload, der innerhalb des Setup-
   Fensters endet, wird erkannt und sein Ergebnis via gepuffertem Kanal
   an `Wait()` zurückgegeben (kein Deadlock, kein Missdeutung als
   Setup-Fehler).
8. **Fremde FDs:** bwrap vererbt unbekannte Deskriptoren absichtlich an
   das Kind (bubblewrap.c: „Any other fds will be passed on to the child“);
   `close_extra_fds` läuft nur im Monitor-/PID-1-Pfad. keg scrubbt
   deshalb selbst: vor dem Start bekommt jeder Deskriptor außer stdio,
   den Kanal-Enden und `Plan.KeepFDs` das Flag `FD_CLOEXEC`
   (`ScrubForeignFDs`, THREAT_MODEL §5.1), und der Guest-Entrypoint
   schließt zusätzlich alles außer 0–5 (`CloseAllFDsExcept`). Der
   Integrationstest `TestInvariant_OnlyPlannedFDsInherit` akzeptiert
   ausschließlich stdio plus Kanal-Sockets (Dups derselben Inode erlaubt,
   wie sie bwraps Setup hinterlässt) — jede Datei/Pipe/fremde Socket in
   der Sandbox ist ein Testversagen.

---

## 4. WP-M2 — Proxy-Kanal (A)

**Status:** ✅ erledigt (Matcher, Host-Proxy, Guest-Bridge, Verdrahtung,
Integrationstest). Umsetzungsnotizen am Abschnittsende.

### 4.1 Whitelist-Matcher

* `Match(domain, patterns) Decision` — exakt + `*.suffix` (Single-Level),
  deterministisch, längster Suffix gewinnt.

**Tests:** Tabellenfälle exakt/Wildcard/Subdomain-Fallen (`evil-golang.org`),
leere Whitelist, Wildcard-vs-exakt-Priorität. ✅ (`TestMatch`,
`TestMatch_LongestSuffixIsDeterministic`)

**Umgesetzt:** Totale Funktion in `internal/egress/proxy`; exakt schlägt
Wildcard, längster Wildcard-Suffix gewinnt, `*.suf.fix` matcht genau ein
Label; Case-Insensitivität + Trailing-Dot-Normalisierung.

### 4.2 CONNECT-Proxy (Host-Seite)

* Request-Parsing (`http.ReadRequest` auf muxado-Stream), 403-Antworten mit
  Begründung, Upstream-CONNECT (`dialViaUpstreamProxy`) mit Statusprüfung,
  vollduplexes Copy mit beidseitigem Timeout-Cleanup.
* Audit-Log: `ERLAUBT/BLOCKIERT <host>` — niemals Payload.

**Tests:** Protokolltests über `net.Pipe()` (echte bwrap-frei):
CONNECT erlaubt/verboten, Upstream verweigert CONNECT ⇒ 502,
Plain-HTTP-Pfad, halboffene Verbindungen leaken keine Goroutinen
(goroutine-leak-check). ✅

**Umgesetzt:** `proxy.Server.Serve(muxado.Session, cfg)`: zweistufige
Filterung (Whitelist vor Dial), CONNECT-Tunneling vollduplex (die zuerst
fertige Richtung schließt beide Enden), Plain-HTTP über
`http.Transport.RoundTrip` inkl. Upstream-Proxy-Funktion, injizierbares
`Dial` für Tests. Audit als strukturierte Callbacks + `FormatAudit`
(golden-getestete Zeilen `ERLAUBT/BLOCKIERT <host:port>` — bewusst
deutsch gemäß CONCEPT/Plan-Vorgabe). *Abweichung von der Testvorgabe:*
die Protokolltests nutzen echte AF_UNIX-Socketpairs statt `net.Pipe()` —
muxados Framer datenriert gegen net.Pipes synchronen Shared-Buffer-
Handover (DATA RACE nur im Testtransport).

### 4.3 Guest-Bridge + Env-Injection

* Bridge lauscht `127.0.0.1:8080`; `HTTP(S)_PROXY`/`NO_PROXY` werden gesetzt.

**Integrationstest:** Sandbox-Client nutzt bash `/dev/tcp` (stdlib, kein
curl-Dependency): CONNECT durch die echte Bridge, Whitelist entscheidet;
zweiter Fall blockiert. ✅ (`TestSandboxProxyChannelDenied`)

**Umgesetzt:** `proxy.Bridge` ist byte-transparent (ein Loopback-Conn =
ein muxado-Stream). Der Workload läuft jetzt **immer** durch den reexec'd
Guest: Launch bindet die keg-Binary ro nach `/.keg` und präfixiert
den Command mit dem Dispatch-Namen; `InitGuestDispatch` bedient beide
Entrypoint-Formen (argv0-Name via reexec, argv[1]-Name via gebundener
Binary). Proxy-Variablen leitet der Guest selbst aus dem `KEG_PROXY`-
Marker ab — NACH dem Env-Strip, damit injizierte Egress-Konfiguration die
Hygiene überlebt, geleakte Host-Proxys aber nicht.

**DoD:** ✅ `keg run -- <cmd>` mit `allowed_domains`: CONNECT zu
whitelisted Domains tunnelt, unbekannte Domain ⇒ sichtbare 403 +
`BLOCKIERT`-Auditzeile auf stderr (offline per Fake-Upstream getestet;
ein echter Internet-CONNECT hängt am realen Netz und bleibt
manueller Smoke-Test).

#### Umsetzungsnotizen M2

1. **Residenter Guest statt exec:** Für Kanäle muss der Guest-Prozess
   überleben, während der Workload läuft. Der Guest startet Bridges, spawn't
   den Workload als Kind, forwardet Signale und spiegelt Exit-Codes
   (Kind-Code verbatim, Signal ⇒ 128+signum, Spawn-Fehler ⇒ 127).
2. **FD-Vertrag verschärft:** Der Workload erbt **nur stdio**; die
   Kanal-Sockets bleiben exklusiv beim Guest. Umsetzung per CLOEXEC-Marking
   statt hartem Close — hartes Close zerstört Runtime-Netpoll-Deskriptoren
   des vollen Go-Binaries (empirisch: `netpoll failed` Fatal). Invariante
   umbenannt: `TestInvariant_WorkloadGetsOnlyStdioFDs`.
3. **Teardown-Reihenfolge Socketpairs:** Rohe Socketpair-FDs sind nicht
   poller-registriert; ein Close auf der Datei weckt blockierende Leser
   nicht. Deshalb: immer erst `muxado.Session.Close()` (weckt alle Streams
   via `die()`), dann `Bridge.Close()`. Getestet in `TestStartProxyBridge`.
4. **Tunnel-Close-Symmetrie:** Bidirektionales Copy schließt bei erster
   beendeter Richtung **beide** Enden — halbseitiges CloseWrite allein
   lässt die Gegenrichtung für immer im Read hängen (Goroutine-Leak).
5. **muxado vs. net.Pipe:** muxados Framer datenriert bei Nutzung von
   `net.Pipe` (synchroner Shared-Buffer-Handover); Tests daher über echte
   AF_UNIX-Socketpairs (Produktionstransport ist ohnehin ein Socketpair).
6. **Env-Hygiene dreistufig:** bwrap `--unsetenv` (M1) + Guest-Unset
   (M1) + Guest-Reapply aus Marker (M2 neu): Die Proxy-Variablen sind
   Teil der Denied-Liste, dürfen aber gezielt wieder gesetzt werden —
   Quelle der Wahrheit ist ausschließlich `KEG_PROXY`.
7. **Fail-closed Bridges:** Schlägt der Bridge-Start fehl, läuft der
   Workload ohne Egress weiter — niemals Fallback auf Host-Netzzugriff.

---

## 5. WP-M3 — DNS-Kanal (B)

**Status:** ⬜ offen.

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

**Status:** ⬜ offen (Teile vorweggenommen: PortSpec-Parsing inkl.
String-/Mapping-Formen sitzt in `internal/config`; `env.set`/`env.unset`
wird bereits vom Arg-Builder angewendet).

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

**Status:** 🔶 teilweise vorweggenommen — plain/`--ephemeral`/
`--disk-overlay NAME` sind seit M1 funktionsfähig (Arg-Builder + CLI-Flags
+ Persistenz-Integrationstest, siehe M1-Umsetzungsnotizen). Offen:
`isolated-cache-name`, Cache-Quellen-Erkennung, Management-Kommandos
(`list`/`clean`/`clean-cache` sind noch Stubs) samt Stufenlöschung und
die EBUSY-Retry-Strategie für das Layer-Lifecycle generalisieren.

* [ ] Modi ephemeral/disk-overlay ~~in den Arg-Builder integrieren~~ ✅;
      offen: isolated-cache-name (Goldentests erweitern); UID-kompatibles
      `mkdirAll` für Upper/Workdirs (aktuell `MkdirAll` mit 0o750 unter
      `paths.storage_base`).
* [ ] Management-Kommandos `list/clean/clean-cache/clean-all` mit
      Stufenlöschung (chmod → unshare-mount → sudo, letzteres interaktiv).

**Tests:** Overlay-Args in Goldens; Layer-Lifecycle-Integrationstest
(erstellen → sichtbar → clean → weg); `--ephemeral` lässt `git status`
jungfräulich.

**DoD:** Alle vier Overlay-Flags verhalten sich wie im Bestand dokumentiert.

---

## 9. WP-M7 — Polish

**Status:** ⬜ offen.

* `log/slog`-strukturiertes Logging; Audit-Datei optional (User-Config).
* Parallel-Instanzen (`--name`, deterministische Pfade).
* Fehlerbild-Katalog als `docs/errors.md` (Texte = Testexpectations).
* Race-Detector sauber; goroutine-leak-check in allen Server-Tests.

---

## 10. WP-M8 — Hardening

**Status:** ⬜ offen.

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

**Status:** ⬜ offen.

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
| Integration (Tag `integration`) | echte bwrap-Läufe (Isolation, FD-Kanäle, Overlay-Persistenz, Env-Hygiene); Offline-Workflows und Playwright-Port-Flow folgen mit M2–M6 | `test/integration/` |
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

**Aktueller Stand:** Phase 0 ✅ · M1 ✅ · M2 ✅ · als nächstes **M3**
(DNS-Kanal B).
Erster nutzbarer Schnitt existiert: isolierte Shell mit Overlay-Modi und
kontrolliertem HTTP(S)-Egress über Kanal A (`allowed_domains`, Audit-
zeilen, Upstream-Proxy aus Host-Umgebung) — DNS-Filterung folgt in M3.
