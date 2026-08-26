# Google Antigravity (`agy`) — Projekt-Konfiguration

Dieses Beispiel demonstriert die Ausführung des Google Antigravity Agenten (`agy`) innerhalb einer hermetischen **keg**-Sandbox, bei der alle Freigaben und Netzwerk-Regeln **direkt im Projekt** ([`.keg.yaml`](file:///home/coder/dev/keg/examples/agy/.keg.yaml)) konfiguriert sind.

---

## 1. Zero-Trust Netzwerk-Konfiguration (`mode: transparent`)

Google Antigravity (`agy`) kommuniziert über gRPC / HTTPS direkt mit Google Cloud Code Endpunkten. Die Sandbox verwendet daher den **Transparent-Modus** (ohne HTTP-Proxy-Umgebungsvariablen):

```yaml
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

### DNS-Auflösung (CoreDNS-Äquivalent)

Die DNS-Anfragen für `*.googleapis.com` werden über den keg-DNS-Resolver auf Loopback `:53` abgefangen, gegen die Whitelist validiert und an den Upstream-DNS weitergeleitet:

```text
googleapis.com:53 {
    forward . 8.8.8.8 1.1.1.1
    log
    errors
}
```

---

## 2. Mounts & Authentifizierung

Damit `agy` innerhalb der Sandbox auf bestehende OAuth-Tokens und das Binary zugreifen kann:

```yaml
mounts:
  - src: ~/.gemini
    dest: /home/sandbox/.gemini
    mode: rw
  - src: ~/.local/bin
    dest: /home/sandbox/.local/bin
    mode: ro
```

---

## 3. Demo ausführen

```bash
# 1. Aus dem Root-Verzeichnis bauen
make build

# 2. agy-Prompt direkt in der Sandbox ausführen:
./bin/keg run --repo examples/agy -- agy -p "sag hi"

# 3. Oder als werfbarer Lauf mit just:
./bin/keg run --repo examples/agy --ephemeral -- just run

# 4. Interaktive agy-Session:
./bin/keg run --repo examples/agy -- agy
```
