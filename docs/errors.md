# Fehlerbild-Katalog (`docs/errors.md`)

Dieser Katalog dokumentiert alle standardisierten Fehlermeldungen, Fehlercodes
und Ursachen in **keg**. Fehlertexte sind Teil der API und durch automatisierte
Tests abgesichert (siehe `AGENTS.md` §1).

---

## 1. Übersicht der Exit-Codes

| Exit-Code | Bedeutung | Kontext |
|---|---|---|
| `0` | Erfolg | Sandbox oder Befehl fehlerfrei beendet |
| `1` | Allgemeiner Konfigurations- oder Startfehler | Ungültige Flags, fehlende Konfiguration, bwrap-Startfehler |
| `125` | Protokollfehler im Delegations-Kanal (Kanal C) | Fehlerhaftes Framing, Pfadausbruch (`job dir escapes repo`) |
| `126` | Delegierter Task abgelehnt | Task oder Raw-Befehl nicht in der Whitelist |
| `127` | Runner nicht verfügbar | Unix-Domain-Socket fehlt oder Runner-Daemon ist nicht aktiv |
| `1..255` | Gast-Befehl-Exit-Code | Exit-Code des ausgeführten Gastprozesses wird transparent durchgereicht |

---

## 2. CLI- und Konfigurationsfehler (Exit-Code 1)

### 2.1 Fehlende Repository-Konfiguration
* **Meldung:** `repo <dir>: open <dir>/.keg.yaml: no such file or directory (create a .keg.yaml or pass --config)`
* **Ursache:** Im aktuellen Arbeitsverzeichnis existiert keine `.keg.yaml` und es wurde kein `--config`-Pfad angegeben.
* **Behebung:** Eine `.keg.yaml` im Repository-Wurzelverzeichnis anlegen (z. B. mit `version: "1"`) oder explizit `--config /pfad/zur/config.yaml` übergeben.

### 2.2 Fehlende explizite User-Konfiguration
* **Meldung:** `load user config: open <path>: no such file or directory`
* **Ursache:** Der über `--user-config` übergebene Pfad existiert nicht auf dem Host.
* **Behebung:** Pfad korrigieren oder das Flag weglassen (die Standard-User-Config unter `$XDG_CONFIG_HOME/keg/config.yaml` ist optional).

### 2.3 Syntax- oder Schemafehler in Konfigurationsdateien
* **Meldung:** `<path>: yaml: unmarshal errors...` oder `<path>: unknown field "<field>"`
* **Ursache:** YAML-Syntaxfehler oder unbekannte Felder in der Repo- bzw. User-Konfiguration (`yaml.v3` `KnownFields(true)`-Validierung).
* **Behebung:** Konfigurationsdatei prüfen und ungültige/unbekannte Direktiven korrigieren.

### 2.4 Gegenseitiger Ausschluss von Overlay-Flags
* **Meldung:** `--ephemeral and --disk-overlay are mutually exclusive`
* **Ursache:** Es wurden gleichzeitig `--ephemeral` und `--disk-overlay <NAME>` übergeben.
* **Behebung:** Entweder `--ephemeral` für flüchtige tmpfs-Overlays oder `--disk-overlay <NAME>` für persistente Disk-Layer wählen.

* **Meldung:** `--isolate-caches and --isolated-cache-name are mutually exclusive`
* **Ursache:** Es wurden gleichzeitig `--isolate-caches` und `--isolated-cache-name <NAME>` übergeben.
* **Behebung:** Entweder `--isolate-caches` (Verwerfen von Cache-Schreibzugriffen) oder `--isolated-cache-name <NAME>` (persistenter benannter Cache-Layer) wählen.

### 2.5 Ungültiger Instanzname
* **Meldung:** `invalid instance name "<name>": must contain only letters, digits, underscores, and hyphens`
* **Ursache:** Der über `--name` bzw. `-n` angegebene Instanzname enthält Leerzeichen, Slashes (`/`), Pfad-Traversal (`..`) oder Sonderzeichen.
* **Behebung:** Nur alphanumerische Zeichen, Bindestriche und Unterstriche verwenden (z. B. `--name worker-1`).

### 2.6 Unbekanntes Sprach-Template
* **Meldung:** `unknown template "<name>" (builtin: go, java, node, python)`
* **Ursache:** Die `.keg.yaml` deklariert ein nicht unterstütztes Template.
* **Behebung:** Ein gültiges integriertes Template angeben oder eigene Mounts/Env-Variablen manuell konfigurieren.

### 2.7 Nicht erlaubte schwächende bwrap-Argumente
* **Meldung:** `bwrap_args contain isolation-weakening flag(s) [...] — set security.allow_weak_bwrap: true in the user config to accept them`
* **Ursache:** Das Ziel-Repository versucht potenziell unsichere Bubblewrap-Flags (z. B. `--share-net`, `--dev-bind /`) zu erzwingen.
* **Behebung:** Wenn beabsichtigt, in der Host-User-Konfiguration (`~/.config/keg/config.yaml`) unter `security.allow_weak_bwrap: true` freigeben.

---

## 3. Egress- und Netzwerkrichtlinien

### 3.1 HTTP(S)-Egress-Proxy (Kanal A)
* **Statuscode:** `403 Forbidden`
* **Body:** `403 Forbidden: domain <host> not whitelisted`
* **Audit-Zeile:** `BLOCKIERT <host>`
* **Ursache:** Ein Prozess im Gast versucht über den Proxy eine Domain zu kontaktieren, die nicht in `network.allowed_domains` gelistet ist.
* **Behebung:** Domain in `network.allowed_domains` bzw. `network.sni_domains` der `.keg.yaml` aufnehmen.

### 3.2 DNS-Auflösung (Kanal B)
* **DNS-Antwort:** `RCODE 3 (NXDOMAIN)`
* **Audit-Zeile:** `DNS BLOCKIERT <name>`
* **Ursache:** Ein DNS-Lookup nach einem Namen, der weder statisch in `network.dns.hosts` noch in `network.allowed_domains` gelistet ist.
* **Behebung:** Domain oder Wildcard (z. B. `*.cluster.local`) in die Whitelist aufnehmen.

### 3.3 Port-Rückkanal (Kanal E)
* **Meldung:** `listen tcp 127.0.0.1:<port>: bind: address already in use`
* **Ursache:** Ein statisch konfigurierter Host-Port in `ports:` ist bereits durch einen anderen Host-Dienst belegt.
* **Behebung:** Port-Nummer in `.keg.yaml` anpassen oder Port `0` für dynamische Port-Vergabe verwenden (`KEG_PORT_<NAME>`).

---

## 4. Host-Delegation (Kanal C)

### 4.1 Unzulässiger Task (Exit-Code 126)
* **Meldung:** `keg delegate: declined: task "<task>" is not whitelisted for delegation`
* **Audit-Zeile:** `DELEGATION BLOCKIERT <task>: task "<task>" is not whitelisted for delegation`
* **Ursache:** Der angeforderte Befehl passt weder auf eine `exact`- noch auf eine `prefixes`- oder `raw`-Regel in `delegated_tasks`.
* **Behebung:** Task in `.keg.yaml` (`delegated_tasks`) oder in der User-Config (`runner.extra_exact`, `runner.extra_prefixes`, `runner.extra_raw`) ergänzen.

### 4.2 Nicht erreichbarer Runner (Exit-Code 127)
* **Meldung:** `keg delegate: runner socket <path>: connect: no such file or directory`
* **Ursache:** `keg delegate` wird in einer Umgebung ohne aktiven Runner-Kanal aufgerufen (z. B. wenn `delegated_tasks` leer war).
* **Behebung:** Delegated Tasks in der `.keg.yaml` deklarieren, sodass keg den Runner-Kanal beim Sandbox-Start initialisiert.

### 4.3 Pfadausbruch im Delegationsauftrag (Exit-Code 125)
* **Meldung:** `job dir "<path>" escapes the repository root`
* **Ursache:** Der Delegationsauftrag versucht über relativen Pfad (`../...`) Verzeichnisse außerhalb des Host-Repositorys anzusteuern.
* **Behebung:** Arbeitsverzeichnis auf einen Pfad innerhalb des Repositorys beschränken.

---

## 5. Storage- & Layer-Management

### 5.1 Nicht gefundener Layer
* **Meldung:** `layer "<name>" not found in <storage_base>`
* **Ursache:** Der angegebene Layer existiert nicht im konfigurierten `storage_base`-Verzeichnis.
* **Behebung:** Namen mit `keg list` prüfen.

### 5.2 Fehlender Parameter bei `keg clean`
* **Meldung:** `clean requires a layer NAME or --all`
* **Ursache:** `keg clean` wurde ohne Argumente aufgerufen.
* **Behebung:** Einen konkreten Layernamen übergeben oder `--all` für alle persistenten Layer nutzen.
