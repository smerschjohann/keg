# Google Antigravity (`agy`) — Nutzer-Konfiguration (In-Sandbox Execution)

Dieses Beispiel demonstriert, wie ein Benutzer **`agy` vollständig isoliert innerhalb der Sandbox** ausführen kann, **ohne** dass das Repository (`.keg.yaml`) etwas von `agy` oder Google-Endpunkten wissen muss:

- **Im Repository ([`.keg.yaml`](file:///home/coder/dev/keg/examples/agy-user-sandbox/.keg.yaml)):**
  Das Git-Repository bleibt völlig sauber und unabhängig.
- **In der Benutzer-Konfiguration ([`user_config.yaml`](file:///home/coder/dev/keg/examples/agy-user-sandbox/user_config.yaml) bzw. `~/.config/keg/config.yaml`):**
  Der Benutzer deklariert die additiven Mounts (`~/.gemini`, `~/.local/bin`) und die Zero-Trust-Netzwerkregeln (`mode: transparent`, DNS, SNI-Domains, TCP-Endpoints).

`keg` merged diese Freigaben beim Start sicher hinzu. `agy` läuft somit **vollständig gesandboxt** unter unprivilegierten Namespaces und Landlock-LSM-Schutz.

> **Secrets-Beispiel:** `user_config.yaml` enthält zusätzlich einen `secret_sources`
> Eintrag `ai_secret_key` mit `always: true` (genkey), der in **jeder** Sandbox als
> `/run/secrets/ai_secret_key` landet — ganz ohne Deklaration im Repo. Kommentierter
> `repos:`-Block zeigt den per-Ziel-Repo-Bedarf. Details zu `always:`/`repos[].secrets`
> siehe [README.md §Secrets aktivieren](../../README.md).

---

## 1. Konfiguration

### Im Projekt ([`.keg.yaml`](file:///home/coder/dev/keg/examples/agy-user-sandbox/.keg.yaml))
```yaml
version: "1"

# Saubere Repository-Konfiguration
```

### In der Nutzer-Konfiguration ([`user_config.yaml`](file:///home/coder/dev/keg/examples/agy-user-sandbox/user_config.yaml))
```yaml
# Additive Mounts für agy
mounts:
  - src: ~/.gemini
    dest: /home/sandbox/.gemini
    mode: rw
  - src: ~/.local/bin
    dest: /home/sandbox/.local/bin
    mode: ro

# Additive Netzwerkfreigaben
network:
  mode: transparent
  dns:
    enabled: true
    hosts:
      lh3.googleusercontent.com: 172.217.113.4
      accounts.google.com: 172.217.113.4
  sni_domains:
    - daily-cloudcode-pa.googleapis.com
    - oauth2.googleapis.com
    - "*.googleapis.com"
    - "*.googleusercontent.com"
    - "*.gstatic.com"
    - accounts.google.com
  tcp_endpoints:
    - host: daily-cloudcode-pa.googleapis.com
      ports: [443]
    - host: oauth2.googleapis.com
      ports: [443]
    - host: www.googleapis.com
      ports: [443]
    - host: lh3.googleusercontent.com
      ports: [443]
    - host: accounts.google.com
      ports: [443]
```

---

## 2. Ausführung

```bash
# 1. Aus dem Root-Verzeichnis bauen
make build

# 2. agy gesandboxt ausführen:
./bin/keg run --repo examples/agy-user-sandbox --user-config examples/agy-user-sandbox/user_config.yaml -- agy -p "sag hi"

# 3. Oder als werfbarer Lauf mit just:
./bin/keg run --repo examples/agy-user-sandbox --user-config examples/agy-user-sandbox/user_config.yaml --ephemeral -- just run
```
