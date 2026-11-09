# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# Two image targets:
#
#   binary  - FROM scratch: nothing but the statically linked keg binary. A
#             transport artifact (docker cp, CI runners, image base). It
#             cannot run sandboxes: bwrap, unshare and a userland are absent.
#             No CA bundle and no TMPDIR: the only commands that would need
#             them (keg run) need bwrap anyway.
#   runtime - keg plus the host-side toolchain it shells out to, on a glibc
#             userland: bubblewrap (>= 0.11 for overlay mounts), unshare from
#             util-linux, ip (iproute2) and nft (nftables) for transparent
#             egress mode. This is the image described in
#             docs/container-requirements.md.

FROM scratch AS binary
ARG TARGETARCH
ARG VERSION=dev

COPY --chmod=0755 dist/keg_linux-${TARGETARCH} /keg

LABEL org.opencontainers.image.title="keg" \
      org.opencontainers.image.description="Kernel-isolated execution with gateways (binary only)" \
      org.opencontainers.image.source="https://github.com/smerschjohann/keg" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.base.name="scratch"

ENTRYPOINT ["/keg"]
CMD ["--help"]

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS runtime
ARG TARGETARCH
ARG VERSION=dev

# bubblewrap >= 0.11 is required for --overlay-src/--tmp-overlay; the build
# fails loudly instead of shipping an image keg would reject at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bubblewrap \
      ca-certificates \
      iproute2 \
      nftables \
      util-linux \
 && rm -rf /var/lib/apt/lists/* \
 && dpkg --compare-versions "$(bwrap --version | awk '{print $2}')" ge 0.11 \
 && command -v bwrap unshare ip nft

COPY --chmod=0755 dist/keg_linux-${TARGETARCH} /usr/local/bin/keg

LABEL org.opencontainers.image.title="keg" \
      org.opencontainers.image.description="Kernel-isolated execution with gateways (runtime with sandbox toolchain)" \
      org.opencontainers.image.source="https://github.com/smerschjohann/keg" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/debian:trixie-slim"

ENTRYPOINT ["/usr/local/bin/keg"]
CMD ["--help"]
