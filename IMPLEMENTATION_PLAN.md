# keg — Kernel-isolated Execution with Gateways — Implementierungsplan

> Operative Ausarbeitung der Meilensteine M1–M9 aus `CONCEPT.md`.
> Sicherheitsinvarianten: `THREAT_MODEL.md` §8 (jede ist regressionsgetestet).
> Arbeitsregeln für Coding-Agents: `AGENTS.md`.
>
> **Status-Tracker:** Jeder WP-Kopf trägt seinen Umsetzungsstand.
> Stand: **Phase 0 + M1–M7 vollständig** (inkl. Transparent-Modus,
> Port-Rückkanal, Delegations-Kanal C, isolierten Cache-Overlays,
> Layer-Management mit Stufenlöschung, Parallel-Instanzen via `--name`,
> `log/slog`-Struktur/Audit-Logging und Fehlerbild-Katalog in `docs/errors.md`).
> Abweichungen vom Originalplan sind als
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

**Status:** ✅ erledigt — mit wesentlichem Architektur-Gewinn: Die Sandbox
bekommt einen **echten DNS auf 127.0.0.1:53** (resolv.conf-kompatibel).
Umsetzungsnotizen am Abschnittsende.

**Umgesetzt:**

* Framing-Codec `internal/frame`: `ReadFrame/WriteFrame`
  (2-Byte-Length-Prefix, RFC 1035 §4.2.2) — wiederverwendbar für den
  Runner-Protokollkanal (M5). Tests: Roundtrip, Truncation, EOF,
  Sequenz.
* Resolver-Kern (`internal/egress/dns.Resolver`): hosts-Mappings
  (exakt vor längstem Wildcard-Suffix) → Whitelist (Zonen-Semantik) →
  Upstream (`miekg/dns`, UDP, Timeout) → NXDOMAIN. FORMERR bei kaputten
  Queries; Response-ID echo garantiert.
* **Netns-Stage** (`internal/orchestrator/netns.go`): Launch wrapt bwrap in
  eine keg-eigene user+network Namespace-Kombination (unshare(1),
  UID-mapped, `--keep-caps`). Die Stage bringt `lo` hoch, senkt
  `ip_unprivileged_port_start`, bindet UDP+TCP :53 und exec'd bwrap mit
  `--share-net` — die Sandbox teilt diese Namespace. Queries wandern
  gerahmt über den fd4-Socketpair zur hostseitigen Policy.
* resolv.conf-Injektion (`nameserver 127.0.0.1`) funktioniert damit wieder;
  statische `dns.hosts`-Mappings werden zusätzlich als generierte
  `/etc/hosts` gebunden (native Auflösung ohne DNS-Roundtrip).
* Standard-Upstream = Host-Resolver (Zielumgebung: kube-dns; externes DNS
  ist unerreichbar).

**Tests:** Codec-Roundtrip/-Truncation; Resolver-Tabellentests (hosts exakt
und Wildcard, Zonen-Tiefe multi-level, Whitelist-Fehlschlag ⇒ NXDOMAIN,
Upstream-Ausfall ⇒ SERVFAIL, ID-Echo); Bridge-Lasttest (100 parallele
Queries, keine Drops); Integrationstest löst
`kubernetes.default.svc.cluster.local` über :53 via kube-dns auf und prüft
NXDOMAIN für Nicht-Whitelisted (`TestSandboxDNSChannel`).

**DoD:** ✅ DNS-Queries laufen ausschließlich über Kanal B (:53 im privaten
Namespace); Deny-by-default per NXDOMAIN; Whitelist geteilt mit Kanal A
(Zonen-Semantik). Audit-Zeilen für DNS folgen mit dem zentralen Audit-Log
(M7).

### 5.1 Transparent-Modus & tcp_endpoints (M3-Fortschreibung)

**Status:** ✅ erledigt — SNI-Splicing und rohes TCP-Passthrough laufen
End-to-End gegen echte nftables/Conntrack (Integrationstests grün).

* `network.mode: transparent` — für Proxy-ignorierende Workloads:
  Stage baut minimales Netz (Pod-IP auf lo, Default-Route via lo), nftables
  redirectet TCP auf konfigurierte Ports zu einem Relay in der Stage;
  Policy bleibt vollständig hostseitig.
* **Zwei getrennte Policy-Mechanismen**, in der Config am Feldnamen
  unterscheidbar:
  * `sni_domains`: name-basiert, TLS :443 (SNI-Peek, kein MITM; ECH ⇒
    fail-closed); bewusst Single-Level-Matching (M3-Notiz 5);
  * `tcp_endpoints` (`host` + `ports[]`): rohes TCP via DNS-Korrelation —
    der Resolver merkt sich forwarded A-Antworten erlaubter Namen in einer
    IP→Endpoint-Tabelle (TTL: `DefaultRawCorrelationTTL`, 30 s); der Proxy
    prüft IP-literale CONNECT-Ziele dagegen (`RawTargetCheck`, inkl.
    Port-Pinning).
* Upstream-Dial weiterhin hostseitig ⇒ keine Loop-Gefahr, FQDNNetworkPolicy-
  Semantik im Pod-Netz bleibt unberührt.
* Verdrahtung: `tcp_endpoints`-Hosts joinen die DNS-Whitelist und aktivieren
  Kanal B; Kanal A startet bei `sni_domains` **oder** `tcp_endpoints`
  (`TestBuildRunPlan_TCPEndpointsJoinDNSWhitelist`).

**Tests:** `TestSandboxRawTCPPassthrough` (Fake-Upstream-DNS + Echo-Origin +
`/dev/tcp`: Redirect → SO_ORIGINAL_DST → CONNECT → Korrelation → Tunnel;
unkorrelierte IP auf demselben Port wird verweigert);
`TestSandboxTransparentMode` (echtes Cluster-Endpoint über gesplictes SNI-TLS,
keine Proxy-Vars, Deny für Nicht-Whitelisted);
`TestRelay_*` (Relay-Dispatch mit injizierter Original-Destination,
Fail-Closed-Fälle);
`TestRulesetReader_RedirectsAndEnforcement` (Regelsatz-Form gepinnt);
`TestRawEndpoints_*` (Korrelation, TTL, Port-Pinning).

#### Umsetzungsnotizen Transparent-Modus (empirisch verifiziert)

1. **Output-Hook-Falle:** Ein Default-Drop als Output-Filterkette killt jeden
   Flow: nftables reroutet redirectete Pakete erst NACH allen Output-Hooks —
   die Filterkette sieht die Pre-NAT-Zieladresse (und auch noch nicht gesetzte
   Marks). Enforcement liegt daher im **postrouting**: dort ist die übersetzte
   Adresse sichtbar; `ct state established,related` lässt ausschließlich
   Antworten inspizierter Flows passieren, alles Neue zu fremden Zielen wird
   gedroppt.
2. **Quelladresswahl:** Im privaten Netns existiert die Pod-IP nicht — connect()
   wählt 0.0.0.0 als Quelle und Relay-Antworten finden den Client-Socket nie
   (Blackhole). Der Stage pinnt deshalb die Host-Egress-IPv4 (`OutboundIPv4`,
   reiner Route-Lookup ohne Paketversand) per `ip addr add …/32 dev lo`.
3. **SO_ORIGINAL_DST funktioniert unter nftables REDIRECT** wie unter iptables:
   getsockopt(SOL_IP, 80) liefert Pre-NAT-IP+Port; Parser verwirft Müll
   (falsche Family, Nulladresse/-Port) ⇒ fail-closed statt implizitem Allow.
4. **Dispatch im Relay:** Erstes Peek-Byte entscheidet — 0x16 ⇒ TLS-Pfad
   (ClientHello akkumulieren, SNI oder Ende); jedes andere Byte ⇒ Raw-Pfad
   zur Pre-NAT-Zieladresse. Ohne wiederherstellbare Original-Destination wird
   geschlossen (fail-closed, keine fixe Zielannahme mehr).
5. **Deny-Erkennung im Test:** `head -c N` exit-t bei sofortigem EOF mit 0 —
   Deny-Fälle prüfen den gelesenen Output, nicht den Exit-Code.

**Umsetzungsnotizen (empirisch):** bwrap leert das Capability-Bounding-Set
(:53/:443 nie bindbar aus dem Sandbox-Baum); glibc kennt keine Portsyntax
in resolv.conf; fake-root-Mapping (`unshare -r`) bricht bwraps
unprivilegierten Pfad ⇒ UID-1:1-Mapping + `--keep-caps` + Cap-Drop vor
exec; per-Netns-Sysctl `ip_unprivileged_port_start=0` macht Standardports
für den cap-less Workload erreichbar; doppeltes `os.NewFile` aufs selbe FD
bricht die Poller-Registrierung.

#### Umsetzungsnotizen M3 (empirisch verifiziert)

1. **Port 53 unter reinem bwrap unmöglich:** bwrap leert das Capability-
   Bounding-Set komplett (CapEff/CapBnd=0), und der frische Netns gehört
   dem Host-UserNS — niemand im Sandbox-Baum kann je :53 binden. Erste
   Implementierung wich auf :5353 aus, aber glibc kennt keine Portsyntax
   in resolv.conf (`nameserver ip:port` wird ignoriert) ⇒ toter Code.
2. **Lösung: Netns-Wrapper.** unshare(1) erzeugt user+netns gemeinsam
   (UID-Mapping 1000→1000 — NICHT `-r`: fake-root lässt bwrap in den
   privilegierten Pfad laufen und er verweigert), `--keep-caps` erhält die
   Caps bis in die Stage. Dort: lo up (SIOCSIFFLAGS-Ioctl), Port-Floor 0
   (per-Netns-Sysctl!), :53 binden, dann **alle Caps droppen**
   (capset v1, Magic 0x19980330) — bwrap verweigert sonst „Unexpected
   capabilities" — und exec bwrap mit `--share-net`.
3. **Upstream-Erreichbarkeit:** Die private Netns hat keine Routen. Der
   Stage-Relay schickt Whitelist-Queries daher gerahmt über fd4 zum
   Orchestrator zurück; Policy + Upstream-Dial laufen hostseitig. Die
   Stage ist reines Relay (keine Policy) — gleiches Trust-Modell wie
   vorher der Gast-Bridge-Ansatz.
4. **FD-Hygiene doppelt genäht:** Channel-FDs werden in der Stage genau
   einmal gewrappt und von allen Konsumenten geteilt (Doppel-`os.NewFile`
   aufs selbe FD bricht die Poller-Registrierung — empirisch: Timeouts).
5. **DNS-Whitelist mit Zonen-Semantik:** `*.svc.cluster.local` matcht
   beliebige Tiefe (kubernetes.default.svc.cluster.local) — Kubernetes-
   Namen tragen mehrere Labels vor der Zone. Der Proxy bleibt bewusst
   Single-Level (SNI-Modell); beide Matcher sind getrennte Funktionen.
6. **Default-Upstream = Host-Resolver:** In der Zielumgebung ist externes
   DNS unerreichbar; Cluster-Namen via kube-dns sind der relevante Fall
   (getestet). Explizites `dns.upstream` überschreibt weiterhin.
7. **Isolation unverändert:** Die Wrapper-Netns enthält nur `lo`, keine
   Routen; der Workload läuft cap-less (Bounding-Set leer). THREAT_MODEL
   §5.1/§5.2 entsprechend nachgezogen.

---

## 6. WP-M4 — Templates, Vars, Env, Ports

**Status:** ✅ erledigt — §6.1–§6.4 komplett (Template-Engine, first-class
env/bwrap_args, Sprach-Templates mit Toolchain-Erkennung, Port-Rückkanal
Kanal E inkl. Integrationstests). Umsetzungsnotizen am Abschnittsende.

### 6.1 Template-Engine (`internal/template`) — ✅

* Kontext **nur** `.Vars`, `.Env`; einzige Funktion `default`; alle anderen
  Funktionen (auch text/template-Builtins wie printf) ⇒ harter Fehler mit
  Zeilenreferenz.
* Fehlende Var außerhalb von `default` ⇒ Fehler mit Zeilenreferenz;
  innerhalb von `default` ist sie der intendierte Fallback-Auslöser.
* `allow_env=false` (Default) ⇒ jeder `.Env`-Zugriff = Konfigurationsfehler,
  der die aktivierende Flagge nennt (THREAT_MODEL §8: Host-Umgebung wird
  nie implizit exponiert).
* `Vars`-Merge: Repo → User global → repos[match] (`KEG_VAR_*` folgt).
* Anwendungsfelder umgesetzt: mounts src/dest, dns.hosts-Werte, env.set-
  Werte, ports-Namen. Alles Übrige bleibt literal by construction.

### 6.2 First-class `env` & `bwrap_args` — ✅

* unset-vor-set Semantik (`TestBuildArgs_EnvUnsetBeforeSet`); Werte aus
  `env.set` sind template-bar (`resolveTemplates`, Feldpfad im Fehler);
  Weak-Flag-Gate für `bwrap_args` inkl. Root-Bind-Erkennung (aus 3.2,
  Goldentests gepinnt).

### 6.3 Sprach-Templates (builtin) — ✅

* go/java/node/python als Datenstrukturen (`config.ExpandTemplates`, rein);
  Cache-Quellen-Erkennung (`DetectToolchainPaths` über `go env GOMODCACHE /
  GOCACHE / GOROOT` mit Injektions-Seams); fehlendes Go ⇒ leere Pfade,
  keine Mounts (fail-closed), Sandbox-Side-Locations bleiben gesetzt.
* GOROOT-Mapping: liegt der GOROOT außerhalb von `/usr`, wird er ro an
  seinen eigenen Pfad gebunden und `GOROOT/bin` vor den PATH gestellt
  (`Plan.ExtraPathDirs`).
* Additiv: mehrere Templates kombinieren Env+Mounts; explizite
  `env.set`-Werte schlagen Template-Defaults.

**Integrationstest:** `TestSandboxGoTemplateOfflineBuild` — Host-Warm-Build
füllt Cache-Fixtures, Sandbox-Build läuft offline daraus (`go version &&
go build -o hello . && ./hello`).

### 6.4 Port-Rückkanal (Kanal E) — ✅

* Parser sitzt seit Anfang in `internal/config`; Auflösung/Dynamic-
  Allocation/Framing/Forwarder in `internal/portsfw`:
  * `Resolve(specs, alloc)` — dynamische Ports werden **vor** dem Launch
    durch echtes Binden von `127.0.0.1:0` reserviert; der Listener selbst
    IST die Reservierung (kein Steal-Fenster zwischen Planung und Serve).
  * Framing je Stream: 2-Byte-Big-Endian-Zielport (`EncodeTarget/
    DecodeTarget`, Werte außerhalb 1..65535 abgelehnt), danach raw Bytes.
  * Guest-Forwarder (`ServeGuest`) dialt ausschließlich deklarierte Ziele
    auf dem Sandbox-Loopback; alles andere wird ohne Dial geschlossen
    (Deny-by-default, Allowlist per `KEG_PORTS`-Marker;
    `TestInvariant_PortChannelGuestDenyList` pinnt das End-to-End).
  * Host-Seite (`Sandbox.StartPortsForward`): Listener **ausschließlich**
    auf 127.0.0.1; statische Kollision ⇒ klarer Fehler mit Adresse.
* Kanalfd 6 (`FDPorts`), `FDPreserved=4`; Stage reicht fd 3..6 durch.
* `KEG_PORT_<NAME>` für benannte Einträge in der Sandbox-Env.

**Tests:** Parser-/Resolve-/Env-/Framing-Tabellentests; End-to-End über
AF_UNIX-Socketpairs (`TestChannelE_EndToEnd` mit Goroutine-Leak-Check);
Integrationstests: dynamischer Dev-Server + statischer Port vom Host-Loopback
aus erreichbar (`TestSandboxPortBackChannel`), Deny-Liste
(`TestInvariant_PortChannelGuestDenyList`).

**DoD:** ✅ Playwright-artiger Workflow: Dev-Server in der Sandbox, Host-curl
auf `127.0.0.1:<port>` antwortet.

#### Umsetzungsnotizen M4

1. **Port-Env-Namen sanitisiert:** CONCEPT.md §4.9 zeigt
   `KEG_PORT_dev-server` — ein Bindestrich ist in Shells nicht
   referenzierbar (`$KEG_PORT_dev-server` parst als Subtraktion).
   Namen werden auf `[A-Z0-9_]` gemappt: `KEG_PORT_DEV_SERVER`.
2. **Reservierung durch Binden statt Port-Picken:** „Freien Port suchen und
   wieder freigeben“ hat ein Race-Fenster; keg bindet :0 und behält den
   Listener bis zum Start des Forwardings. `ResolvedPort.Listener` trägt
   die Reservierung durch alle Ebenen.
3. **muxado-Accept wacht nicht von selbst auf:** Das Session-Close des
   Partners beendet `Accept()` nicht zuverlässig — `ServeGuest` nimmt daher
   einen Context, dessen Abbruch die eigene Session schließt (gleiche
   Teardown-Reihenfolge wie Kanal A: erst Session, dann darauf Ruhende).
4. **Templates vor Repo-Env mergen:** Template-Defaults gehen zuerst in die
   Env, `env.set` gewinnt Konflikte — Templates bleiben additive Bausteine.
5. **Tilde-Quellen:** Template-Mounts nutzen `~/.m2` etc. literal und werden
   wie User-Mounts beim Planbau expandiert — eine Quelle der Wahrheit für
   Pfad-Expansion.

---

## 7. WP-M5 — Delegation (Kanal C)

**Status:** ✅ erledigt (§7.1 und §7.2 vollständig implementiert, unit-getestet und durch bwrap-basierten End-to-End-Integrationstest `TestSandboxDelegation` verifiziert).

**Umgesetzt:**

* Whitelist-Engine `internal/runner`: Klassen exact/prefix/raw,
  fünfstufiger Raw-Matcher nach CONCEPT.md §4.5 (globale Optionen mit/
  ohne Wert inkl. `--opt=value` nur mit Freigabe),
  `forbidden_args_matching` als URL-tauglicher Glob (`*`/`?` spannen
  auch `/`) oder `/Regex/`; User-`extra_*` unionieren
  (`TestNewEngine_MergesUserExtrasAsUnion`); Invariante
  `TestInvariant_DelegationDenyByDefault`.
* Runner-Server: ein muxado-Stream pro Job; Request = ein
  Length-Prefix-JSON-Frame mit base64-codierten Argumenten
  (mehrzeilige Commit-Messages überleben die Übertragung unverändert);
  stdout/stderr werden live als Frames gestreamt, danach folgt der
  Exit-Marker bzw. `denied`/`error`. Jobs laufen in eigener Prozessgruppe
  und sterben mit dem Sandbox-Kontext (`WaitDelay` reapt Nachzügler).
* Pfad-Jail via `filepath.Rel` gegen den Repo-Root; absolute Pfade,
  Traversale und nicht existierende Verzeichnisse ⇒ Fail-Closed-Fehler
  (`TestServer_PathJailBlocksEscapes`).
* Git-Hook-Unterdrückung: raw-git-Jobs bekommen `-c core.hooksPath=
  <leeres keg-Dir>` vorangestellt
  (`TestServer_SuppressesGitHooksForRawGitJobs`).
* Verdrahtung: `buildRunPlan` übergibt `delegated_tasks` + User-Extras +
  bestand-kompatibles `RUNNER_WHITELIST`-Env an die Engine, setzt den
  `KEG_RUNNER`-Marker, mountet `/run` (tmpfs) und legt das leere
  Hooks-Dir pro Instanz an; `keg run` serviert `StartRunner` auf
  Kanal C bis `Sandbox.Close`. Guest bindet `/run/keg/runner.sock`
  (fd 5 → Bridge → Unix-Socket). CLI: `keg delegate <argv…>` mappt
  Job-Code verbatim / 126 verweigert / 125 Protokollfehler /
  127 Runner fehlt (In-process-CLI-Tests decken alle vier ab).
  BuildArgs nimmt `/.keg` in PATH auf, sobald das Binary gebunden
  wird.

### 7.1 Whitelist-Engine ✅

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

**DoD:** ✅ Alle Unit- und Integrationstests grün (`TestSandboxDelegation`
reaktiviert und stabil).

#### Umsetzungsnotizen M5 (empirisch verifiziert)

1. **Zweistufige Kanal-C-Topologie:** Dem Sandbox-Workload erscheint
   Delegation als simpler Unix-Socket (`/run/keg/runner.sock`,
   LENGTH-Prefix-JSON direkt über die Verbindung). Die Verbindung wird im
   residenten Guest byte-transparent auf einen eigenen muxado-Stream des
   fd5-Socketpairs gepumpt — getrennte Schichten wie bei Kanälen A/E.
2. **b64-Argumentframing:** Argumente werden Liste-weise base64-codiert
   (`EncodeStrings`/`DecodeStrings`); Newlines, Quotes und `$` in
   Commit-Messages erreichen Host-exec unangetastet (getestet).
3. **muxado-Accept wacht nur beim eigenen Session-Close** (bekannt aus
   M4): ServeSession/Bridge-Stop-Kode schließt deshalb immer zuerst die
   eigene Session.
4. **Reaktivierung TestSandboxDelegation:** Der vermeintliche Accept-Stall
   lag daran, dass in der Integrations-Testsuite das Test-Binary selbst
   an `/.keg/keg` gebunden wurde. Beim Aufruf von `keg delegate`
   im Sandbox-Workload lief das Test-Binary in `TestMain`, welches den
   Subcommand `delegate` nicht abfing, sondern die gesamte Testsuite rekursiv
   im Sandbox-Prozess startete. Durch die Ergänzung des `delegate`-Dispatches
   in `TestMain` ist der E2E-Lauf vollständig funktionsfähig und grün.
5. **RUNNER_WHITELIST bleibt Kompatibilitäts-Oberfläche:** komma-
   separierte exact-Tasks aus dem Host-Env, Trim vor Merge, wirken
   zusätzlich zur Repo-Config (`TestBuildRunPlan_RunnerWhitelistEnvCompat`).

---

## 8. WP-M6 — Overlays & Layer-Management

**Status:** ✅ erledigt (inkl. `--isolate-caches`, `--isolated-cache-name`, `list`/`clean`/`clean-cache` und Stufenlöschung).

* [x] Modi `ephemeral` und `disk-overlay` in Arg-Builder & CLI integriert.
* [x] Modi `--isolate-caches` (ephemeres tmp-overlay über Cache-Mounts) und `--isolated-cache-name NAME` (persistente Disk-Layer `<storage_base>/cache-<NAME>/...` via `MountEphemeral`/`MountDisk`).
* [x] Cache-Quellen-Erkennung und User-Config-Overrides (`paths.go_mod_cache`, `paths.go_build_cache`).
* [x] EBUSY-Retry-Strategie für alle Overlay-Mounts generalisiert (`Plan.HasOverlay()`).
* [x] Management-Kommandos `list`, `clean`, `clean-cache` in `internal/storage` & CLI mit Stufenlöschung (chmod 0700/0600 → unshare -r mount → sudo).

**Tests:** Overlay-Args & Cache-Overlays in Unit-Tests; CLI-Flags & Mutual-Exclusivity-Tests; Layer-Lifecycle & Cache-Isolations-Integrationstests (`TestSandboxIsolateCaches`, `TestSandboxIsolatedCacheName`, `TestSandboxEphemeralOverlay`, `TestSandboxDiskOverlay`).

**DoD:** ✅ Alle vier Overlay-Flags verhalten sich wie im Bestand dokumentiert; `list`, `clean`, `clean-cache` vollständig funktionsfähig; `make lint test integration` grün.

#### Umsetzungsnotizen M6 (empirisch verifiziert)

1. **Cache-Mount-Modi:** `config.Mount` unterstützt neben `ro`/`rw`/`dev`/`tmpfs` nun `ephemeral` (`--overlay-src <Src> --tmp-overlay <Dest>`) und `disk` (`--overlay-src <Src> --overlay <RW> <WORK> <Dest>`).
2. **Speicher-Hierarchie für Caches:** Persistente Cache-Layer liegen unter `<storage_base>/cache-<name>/{mod,build}-{rw,work}` (entsprechend CONCEPT.md §4.8).
3. **Stufenlöschung (Tiered Deletion):** OverlayFS erzeugt Workdirs mit Mode `0000`. Stufe 1 repariert rekursiv Verzeichnis- (`0700`) und Datei-Rechte (`0600`) vor `os.RemoveAll`; Stufe 2 nutzt `unshare -r --mount rm -rf`; Stufe 3 bietet `sudo rm -rf`-Fallback.
4. **Generalisierte EBUSY-Erkennung:** `Plan.HasOverlay()` deckt sowohl Repo-Overlays als auch Cache-Overlays ab, sodass bwrap-Overlay-Mount-Busy-Races bei allen Overlay-Typen abgefangen und bis zu 10× retry-t werden.

---

## 9. WP-M7 — Polish

**Status:** ✅ erledigt.

* [x] `log/slog`-strukturiertes Logging über alle Komponenten (Proxy, DNS, Runner) und CLI-Verbosity-Flag (`--verbose`/`-v`).
* [x] Optionale Audit-Datei (`log.audit_file` in User-Config) für thread-sicheres Logging aller Whitelist- und Delegationsentscheidungen (`ERLAUBT`/`BLOCKIERT`).
* [x] Parallel-Instanzen via `--name NAME` (`-n`) mit deterministischen Instanzverzeichnissen `<tmp_base>/keg-<NAME>` und strenger Namensvalidierung.
* [x] Fehlerbild-Katalog als `docs/errors.md` (Texte = Testexpectations).
* [x] Race-Detector sauber (`make test -race` fehlerfrei); Goroutine-Leak-Checks und Session-Cleanup in allen Server-Tests.

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

**Aktueller Stand:** Phase 0 ✅ · M1 ✅ · M2 ✅ · M3 ✅ (inkl. Transparent-
Modus/tcp_endpoints ✅) · **M4 ✅** (§6.1–§6.4) · **M5 ✅** (§7.1, §7.2
vollständig inkl. e2e) · **M6 ✅** (Overlay-Modi, Cache-Isolation, Layer-Management, Stufenlöschung) · **M7 ✅** (Parallel-Instanzen, Audit/Slog-Logging, Fehlerkatalog).
Erster nutzbarer Schnitt nach M5/M6/M7 vollständig für den Bestands-Workflow nutzbar:
isolierte Shell mit allen Overlay-Modi (ephemeral, disk-overlay, isolate-caches,
isolated-cache-name) sowie Layer-Management (list/clean/clean-cache),
parallelen benannten Instanzen (`--name`), zentralem structured Logging & Audit-Datei,
kontrolliertem HTTP(S)-Egress (Kanal A) und echtem whitelist-filternden DNS auf
:53 (Kanal B) inklusive cluster.local-Auflösung über kube-dns — wahlweise im
Proxy- oder Transparent-Modus (rohes TCP via DNS-Korrelation) sowie
Port-Rückkanal (Kanal E) und sichere Host-Delegation (Kanal C).
