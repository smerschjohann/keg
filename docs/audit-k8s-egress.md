# Sicherheits-Audit: Isolationstest & Egress-Bypass-Analyse (Kubernetes API)

> **Datum:** 2026-08-26  
> **Zielkomponente:** keg Sandbox & Zero-Trust Egress-Filterung  
> **Zieladresse:** `kubernetes.default.svc.cluster.local` (und K8s Control Plane Endpoints)  
> **Status:** Bestanden (Vollständig blockiert / Fail-Closed)

---

## 1. Management Summary

Im Rahmen eines automatisierten Penetrationstests / Sicherheits-Audits wurde die Isolation der `keg`-Sandbox gegen unautorisierten Zugriff auf clusterinterne Kubernetes-Dienste (`kubernetes.default.svc.cluster.local`, Cluster-IPs, K8s-API-Server auf Ports `443`/`6443`) getestet.

**Ergebnis:** Alle Angriffs- und Bypass-Vektoren wurden auf mehreren Verteidigungsebenen (Defense-in-Depth) erfolgreich abgewehrt:
* **DNS-Ebene:** Strikte NXDOMAIN-Antworten (Deny-by-Default).
* **Netzwerk-Ebene:** Kein Routing jenseits des Loopback-Interfaces; direkte IP-Verbindungsversuche laufen in Timeouts.
* **Proxy-Ebene:** Unmittelbarer Abbruch von HTTP CONNECT-Tunnelanfragen und HTTP-Requests bei nicht-whitelisted Zielen.
* **Dateisystem-/Secret-Ebene:** Keine ServiceAccount-Tokens oder Cluster-Secrets im Dateisystem oder Environment auffindbar.

---

## 2. Testmatrix & Angriffsszenarien

| # | Angriffsvektor | Getestete Payloads / Methoden | Erwartetes Verhalten | Reales Verhalten | Status |
|---|---|---|---|---|---|
| **T1** | Direkte DNS-Auflösung | `kubernetes.default.svc.cluster.local`, `kubernetes.default.svc`, `kubernetes.default`, `kubernetes` | `NXDOMAIN` (Deny-by-Default) | `NXDOMAIN` über `127.0.0.1:53` | **BLOCKIERT** |
| **T2** | DNS-Bypass via Upstream/K8s-IPs | Queries an `10.96.0.10`, `10.43.0.10`, `10.0.0.10`, `1.1.1.1`, `8.8.8.8` | Abfangen / Weiterleitung an Policy | `NXDOMAIN` (kein Out-of-Band DNS) | **BLOCKIERT** |
| **T3** | Direktes IP-Dialing (TCP/TLS) | `10.96.0.1:443`, `10.43.0.1:443`, `10.0.0.1:443`, `172.30.0.1:443`, `192.168.100.200:6443` | Verbindungsabbruch / Timeout (kein Egress) | `Connection timed out` (Fail-Closed) | **BLOCKIERT** |
| **T4** | HTTP CONNECT Proxy-Bypass (:7443) | FQDNs, Trailing Dots (`.`), Case Variations, Short-Names, IP-Literale | Proxy-Abbruch (Verbindungs-Reset) | `Proxy CONNECT aborted` | **BLOCKIERT** |
| **T5** | HTTP Absolute-URI Requests | `GET http://kubernetes.default.svc.cluster.local/` | Request-Ablehnung / Drop | Sofortiger TCP-Close ohne Antwort | **BLOCKIERT** |
| **T6** | ServiceAccount Token-Exfiltration | Suche nach `/var/run/secrets/kubernetes.io/serviceaccount/*`, Kubeconfigs, Env-Vars | Keine Credentials zugänglich | Keine Tokens/Secrets gefunden | **BLOCKIERT** |

---

## 3. Detail-Auswertung der Testvektoren

### 3.1 DNS-Auflösung (Test T1 & T2)

**Testdurchführung:**
```bash
for host in kubernetes.default.svc.cluster.local kubernetes.default.svc kubernetes.default kubernetes; do
    nslookup $host 127.0.0.1
done
```
**Audit-Log:**
```text
Server:     127.0.0.1
Address:    127.0.0.1#53

** server can't find kubernetes.default.svc.cluster.local: NXDOMAIN
```
**Bewertung:** Gemäß `THREAT_MODEL.md` §5.2 antwortet der gefilterte DNS-Resolver (Kanal B) bei Namen außerhalb der Whitelist mit `NXDOMAIN`. Auch der Versuch, DNS-Pakete direkt an fremde oder clusterinterne IPs (`10.96.0.10:53`) zu senden, wird durch die Namespace-Isolation bzw. den Stage-Relay abgefangen.

---

### 3.2 Direktes IP-Dialing (Test T3)

**Testdurchführung:**
```bash
for ip in 10.96.0.1 10.43.0.1 10.0.0.1 172.30.0.1 172.30.2.1 192.168.100.200; do
    curl --connect-timeout 1 -k -v https://$ip:443
done
```
**Audit-Log:**
```text
*   Trying 10.96.0.1:443...
* Connection timed out after 1002 milliseconds
* closing connection #0
curl: (28) Connection timed out after 1002 milliseconds
```
**Bewertung:** In Übereinstimmung mit Invariante 2 (Netzwerk-Isolation) besitzt die Sandbox keine direkte Routing-Tabelle zu internen Cluster-Netzen. Rohes TCP ohne vorherige, erlaubte DNS-Korrelation scheitert per Fail-Closed.

---

### 3.3 HTTP CONNECT Tunneling über den Egress-Proxy (Test T4 & T5)

**Testdurchführung:**
Automatisierter Versand von `CONNECT`-Headern an den Egress-Proxy auf `127.0.0.1:7443`:
```bash
exec 3<>/dev/tcp/127.0.0.1/7443
printf "CONNECT kubernetes.default.svc.cluster.local:443 HTTP/1.1\r\nHost: kubernetes.default.svc.cluster.local:443\r\n\r\n" >&3
```
**Audit-Log:**
```text
> CONNECT kubernetes.default.svc.cluster.local:443 HTTP/1.1
> Host: kubernetes.default.svc.cluster.local:443
* Proxy CONNECT aborted
curl: (56) Proxy CONNECT aborted
```
**Bewertung:** Der Proxy validiert die angefragten CONNECT-Ziele strikt gegen die Domain-Whitelist. Alle Varianten (inklusive Groß-/Kleinschreibung, Trailing Dots, Kurznamen und IP-Literale) werden abgewiesen und führen zum sofortigen Schließen des Sockets.

---

### 3.4 Dateisystem- und Secret-Inspektion (Test T6)

**Testdurchführung:**
Prüfung auf ServiceAccount-Mounts und Umgebungsvariablen:
```bash
find / -name "*serviceaccount*" -o -name "*kubeconfig*" 2>/dev/null
env | grep -iE "k8s|kube|service"
```
**Ergebnis:**
* `/var/run/secrets/kubernetes.io/serviceaccount/` existiert nicht.
* Keine clusterweiten Kubernetes-Env-Variablen (`KUBERNETES_SERVICE_HOST` etc.) in die Umgebung geleakt.

---

## 4. Konformität mit dem Bedrohungsmodell (`THREAT_MODEL.md`)

* **TB1 (Mount- & NetNS):** Konform. Kein Egress-Routing jenseits des isolierten Loopback-Interfaces.
* **TB2 (Egress-Kanäle A & B):** Konform. Strikte Whitelist-Prüfung bei HTTP CONNECT (Kanal A) und synthetisches NXDOMAIN bei DNS-Queries (Kanal B).
* **Invariante Fail-Closed:** Verifiziert. Nicht deklarierte Kommunikationsversuche terminieren sofort oder laufen in Timeouts.
