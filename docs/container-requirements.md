# Mindestanforderungen für den Betrieb in Docker / Podman / Kubernetes

`keg` nutzt Linux-Kernel-Namespaces (`user`, `net`, `mnt`, `pid`, `ipc`, `uts`), Bubblewrap (`bwrap`) und `util-linux unshare` für eine hermetische Prozess- und Netzwerk-Isolation. Wenn `keg` selbst **innerhalb** eines Containers (Docker, Podman, Containerd, Kubernetes) betrieben wird, müssen bestimmte Host-Kernel- und Container-Laufzeitanforderungen erfüllt sein.

---

## 1. Übersicht der Mindestanforderungen

| Komponente | Mindestanforderung | Warum erforderlich? |
|---|---|---|
| **Host-Kernel** | Linux ≥ 5.11 (empfohlen ≥ 5.19) | Unprivilegierte User-Namespaces (`CLONE_NEWUSER`), Loopback-Routing und moderne Namespace-Features. |
| **Kernel Sysctl** | `user.max_user_namespaces > 0`<br>`kernel.unprivileged_userns_clone = 1` | Erlaubt das Erzeugen unprivilegierter User-Namespaces für `unshare` und `bwrap`. |
| **Bubblewrap (`bwrap`)** | **`bwrap ≥ 0.11.0`** | `keg` verwendet `--overlay-src` und `--tmp-overlay` für `--ephemeral`- und Layer-Mounts. Ältere Versionen (z. B. `0.8.0` in Debian 12 Bookworm) unterstützen `--overlay-src` nicht. |
| **util-linux** | `unshare` vorhanden | Die `netns`-Stage von `keg` benötigt `unshare -U --map-user=<uid> --map-group=<gid> -n -m -p --fork --keep-caps`. |
| **Container-Capabilities (Root im Container)** | `--cap-add=SYS_ADMIN` | Notwendig, damit der Root-Prozess im Container Namespaces (`unshare`/`clone`) und Mounts anlegen kann. |
| **Container-Seccomp** | Standard-Seccomp oder `seccomp=unconfined` | Manche restriktive Standard-Seccomp-Profile blockieren `unshare` oder `clone3`. |
| **Landlock LSM** | `security.landlock: auto` (Default) | Landlock ist optional / defense-in-depth; im Modus `auto` schlägt der Start nicht fehl, wenn Landlock im Container-Kernel nicht aktivierbar ist. |
| **C-Library / Pfade** | `glibc` (oder `gcompat` auf Alpine), Binaries in `/usr/bin` oder `/bin` | Sandbox mountet standardmäßig `/usr`, `/bin`, `/lib`, `/lib64`. Tools für Host-Delegation (`keg delegate`) müssen im System-Pfad liegen. |

---

## 2. Start-Konfigurationen (Praxis-Beispiele)

### A. Standard-Betrieb (Empfohlen für Docker / Kubernetes / CI)

Wenn der Container-Prozess als `root` (UID 0) im Container startet:

```bash
docker run --rm -it \
  --cap-add=SYS_ADMIN \
  --security-opt seccomp=unconfined \
  -v $(pwd):/workspace \
  -w /workspace \
  mein-keg-image:latest
```

> **Wichtig:** `--cap-add=SYS_ADMIN` reicht in der Regel völlig aus. Der Container benötigt **kein** unsicheres `--privileged`.

---

### B. Betrieb als Unprivilegierter Non-Root-User im Container (UID != 0)

Bubblewrap führt beim Start als Non-Root-Benutzer einen Sicherheitscheck auf *Ambient Capabilities* durch:
> `bwrap: Unexpected capabilities but not setuid, old file caps config?`

Wenn der Container unter einem Non-Root-User (z. B. `--user 1000:1000`) ausgeführt wird, darf dem Container **kein** `--cap-add=SYS_ADMIN` übergeben werden. Stattdessen greift `bwrap` direkt auf unprivilegierte Kernel-User-Namespaces zu:

```bash
# Podman (Rootless mit Benutzer-Mapping):
podman run --rm -it \
  --userns=keep-id \
  -v $(pwd):/workspace \
  -w /workspace \
  mein-keg-image:latest
```

---

### C. Kubernetes Pod / Container Security Context

Für den Einsatz in Kubernetes (z. B. als Build-Runner oder CI-Worker):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: keg-runner
spec:
  containers:
    - name: runner
      image: mein-keg-image:latest
      securityContext:
        capabilities:
          add:
            - SYS_ADMIN
        seccompProfile:
          type: Unconfined  # oder Profil, das unshare/mount erlaubt
      volumeMounts:
        - name: workspace
          mountPath: /workspace
  volumes:
    - name: workspace
      emptyDir: {}
```

---

## 3. Besonderheiten & Dateisystem-Modi

### 1. Ephemeral-Modus (`--ephemeral`)
* Verwendet `tmpfs`-Upper-Layer über Bubblewrap.
* Funktioniert im Container vollständig und isoliert das Host-Repository.
* Erfordert **`bwrap ≥ 0.11.0`**.

### 2. Persistenter Disk-Overlay (`--disk-overlay <name>`)
* Nutzt das Linux-Kernel-`overlayfs` mit `userxattr`.
* **Einschränkung im Container:** Linux erlaubt standardmäßig kein verschachteltes `overlayfs` auf einem bestehenden Container-Overlay-Root-Dateisystem.
* **Lösung:** Wenn `--disk-overlay` im Container verwendet werden soll, muss das Speicherverzeichnis (`paths.storage_base`, Standard: `/var/lib/containers/storage/sandbox`) als externes Volume (Host-Mount mit `ext4`/`xfs` oder separates `tmpfs`) eingehängt werden.

### 3. DNS- & Netzwerk-Egress-Proxy
* Der filternde DNS-Server auf Loopback `:53` und der Egress-Proxy über Kanal A und B laufen über die `netns`-Stage.
* Die `netns`-Stage richtet ein privates Loopback-Interface ein und benötigt keine externen Netzwerk-Privilegien auf dem Container-Host.

---

## 4. Beispiel-Dockerfile

Ein vollständiges Basis-Image für Fedora 40+ oder Debian Trixie/Sid:

```dockerfile
FROM registry.fedoraproject.org/fedora:latest

RUN dnf install -y \
    bubblewrap \
    util-linux \
    procps-ng \
    ca-certificates \
    git \
    && dnf clean all

COPY bin/keg /usr/bin/keg

WORKDIR /workspace
ENTRYPOINT ["/usr/bin/keg"]
CMD ["run"]
```
