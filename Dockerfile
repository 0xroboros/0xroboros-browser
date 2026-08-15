# 0xroboros fork of lightpanda-io/browser (AGPL-3.0-only).
#
# Builds from THIS repository's own local source tree — the Handshake (HNS)
# resolution lanes, the vendored hnsd SPV sidecar, and the agent verdict
# surface — rather than upstream's approach of `git clone`-ing
# lightpanda-io/browser fresh inside the build. That upstream approach would
# silently discard every fork change and ship a vanilla upstream binary
# under our tag; fixed here (browser-p5-distribution, see MODIFICATIONS.md
# "Lane G — distribution").
#
# Multi-arch: TARGETPLATFORM is set by `docker buildx build --platform
# linux/amd64,linux/arm64`; every arch-sensitive step below switches on it,
# matching the upstream Dockerfile's own convention.

FROM debian:stable-slim AS build

ARG MINISIG=0.12
ARG ZIG_MINISIG=RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U
ARG V8=14.9.207.35
ARG ZIG_V8=v0.5.2
ARG TARGETPLATFORM
ARG VERSION=dev

RUN apt-get update -yq && \
    apt-get install -yq --no-install-recommends xz-utils ca-certificates \
        pkg-config libglib2.0-dev \
        clang make curl git \
        autoconf automake libtool libunbound-dev && \
    rm -rf /var/lib/apt/lists/*

# Get Rust (src/html5ever)
# Download then execute (rather than `curl | sh`) so a failed download is not
# masked by sh's exit code under /bin/sh, which has no pipefail.
RUN curl --fail -sSL --retry 3 --retry-delay 2 -o /tmp/rustup.sh https://sh.rustup.rs && \
    sh /tmp/rustup.sh --profile minimal -y && \
    rm /tmp/rustup.sh
ENV PATH="/root/.cargo/bin:${PATH}"

# install minisig
RUN curl --fail -L --retry 3 --retry-delay 2 -O https://github.com/jedisct1/minisign/releases/download/${MINISIG}/minisign-${MINISIG}-linux.tar.gz && \
    tar xzf minisign-${MINISIG}-linux.tar.gz -C /

WORKDIR /browser

# This fork's own source, built in place. Never re-fetched from upstream.
COPY . .

# install zig
RUN ZIG=$(grep '\.minimum_zig_version = "' "build.zig.zon" | cut -d'"' -f2) && \
    case $TARGETPLATFORM in \
      "linux/arm64") ARCH="aarch64" ;; \
      *) ARCH="x86_64" ;; \
    esac && \
    curl --fail -L --retry 3 --retry-delay 2 -O https://ziglang.org/download/${ZIG}/zig-${ARCH}-linux-${ZIG}.tar.xz && \
    curl --fail -L --retry 3 --retry-delay 2 -O https://ziglang.org/download/${ZIG}/zig-${ARCH}-linux-${ZIG}.tar.xz.minisig && \
    /minisign-linux/${ARCH}/minisign -Vm zig-${ARCH}-linux-${ZIG}.tar.xz -P ${ZIG_MINISIG} && \
    tar xf zig-${ARCH}-linux-${ZIG}.tar.xz && \
    mv zig-${ARCH}-linux-${ZIG} /usr/local/lib && \
    ln -s /usr/local/lib/zig-${ARCH}-linux-${ZIG}/zig /usr/local/bin/zig

# Zig 0.16 writes fetched .zip archives (e.g. the sqlite3 amalgamation
# dependency) to <global cache>/tmp but no longer creates that directory,
# so a zip dependency fails with "failed to create temporary zip file:
# FileNotFound" on a fresh cache dir — same issue and same fix as
# .github/actions/install/action.yml's "Zig 0.16 zip-fetch workaround".
# Pinned to an explicit ENV rather than parsed out of `zig env` (fragile —
# its JSON key/value spacing isn't a stable grep target) so the mkdir below
# is guaranteed to match the directory Zig actually uses.
ENV ZIG_GLOBAL_CACHE_DIR=/root/.cache/zig
RUN mkdir -p "${ZIG_GLOBAL_CACHE_DIR}/tmp"

# download and install v8
RUN case $TARGETPLATFORM in \
    "linux/arm64") ARCH="aarch64" ;; \
    *) ARCH="x86_64" ;; \
    esac && \
    curl --fail -L --retry 3 --retry-delay 2 -o libc_v8.a https://github.com/lightpanda-io/zig-v8-fork/releases/download/${ZIG_V8}/libc_v8_${V8}_linux_${ARCH}.a && \
    mkdir -p v8/ && \
    mv libc_v8.a v8/libc_v8.a

# vendor/hnsd/uv (libuv, vendored inside vendored hnsd) ships pre-generated
# autotools output built with automake 1.18; Debian stable's `automake`
# package is 1.17, and its embedded rules invoke the exact versioned
# `aclocal-1.18`/`automake-1.18` binaries by name via the `missing` wrapper,
# which fails "command not found" — not a timestamp/regeneration problem,
# a version-pinned-binary-name problem. Symlinking the versioned names to
# whatever aclocal/automake is actually installed resolves it regardless of
# whether Make decides regeneration is needed.
RUN ln -sf "$(command -v automake)" /usr/local/bin/automake-1.18 && \
    ln -sf "$(command -v aclocal)" /usr/local/bin/aclocal-1.18

# build hnsd (vendored at vendor/hnsd, MIT, pinned commit — see
# vendor/hnsd/VENDORED_COMMIT). Off the default `zig build`, so this step is
# explicit: autotools bootstrap (autoconf/automake/libtool + libunbound-dev,
# installed above) producing vendor/hnsd/hnsd, which --hnsd-path/the default
# search order picks up automatically (see src/help.zon).
RUN zig build hnsd

# build v8 snapshot
RUN zig build -Doptimize=ReleaseFast \
    -Dprebuilt_v8_path=v8/libc_v8.a \
    snapshot_creator -- src/snapshot.bin

# build release
RUN zig build -Doptimize=ReleaseFast \
    -Dsnapshot_path=../../snapshot.bin \
    -Dprebuilt_v8_path=v8/libc_v8.a \
    -Dversion=${VERSION}

FROM debian:stable-slim AS tini

RUN apt-get update -yq && \
    apt-get install -yq --no-install-recommends tini && \
    rm -rf /var/lib/apt/lists/*

FROM debian:stable-slim

ARG VERSION=dev

LABEL org.opencontainers.image.title="0xroboros Browser" \
      org.opencontainers.image.description="Agent-drivable headless browser with native Handshake (HNS) name resolution and DANE/TLSA authentication. AGPL-3.0-only fork of lightpanda-io/browser; not affiliated with or endorsed by Lightpanda (Selecy SAS)." \
      org.opencontainers.image.source="https://github.com/0x13omb3r/0xroboros-browser" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}"

# ca-certificates: standard ICANN/WebPKI TLS. libunbound8: runtime dependency
# of the vendored hnsd sidecar (dynamically linked; see vendor/hnsd/README.md
# "Dependencies").
RUN apt-get update -yq && \
    apt-get install -yq --no-install-recommends ca-certificates libunbound8 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /browser/zig-out/bin/0xroboros-browser /bin/0xroboros-browser
COPY --from=build /browser/vendor/hnsd/hnsd /bin/hnsd
COPY --from=build /browser/LICENSE /LICENSE
COPY --from=build /browser/MODIFICATIONS.md /MODIFICATIONS.md
COPY --from=build /browser/vendor/hnsd/LICENSE /THIRD_PARTY_LICENSES/hnsd-LICENSE-MIT
COPY --from=tini /usr/bin/tini /usr/bin/tini

EXPOSE 9223/tcp

# Upstream telemetry defaults to ON (src/telemetry/lightpanda.zig, reporting
# to telemetry.lightpanda.io) and is disabled by this variable simply being
# present in the environment (any value, including empty — see
# src/telemetry/telemetry.zig, `getenv(...) != null`). A redistributed fork
# phoning home to the upstream vendor's own endpoint by default is a
# distribution default this image should not carry silently
# (trademark/endorsement posture — see the phase result's trademark
# report); disabled here. Because presence alone (not value) is what
# matters, this cannot be "re-enabled" via `docker run -e`; an image built
# without this line is the way to opt back in.
ENV LIGHTPANDA_DISABLE_TELEMETRY=1

# Lightpanda install only some signal handlers, and PID 1 doesn't have a default SIGTERM signal handler.
# Using "tini" as PID1 ensures that signals work as expected, so e.g. "docker stop" will not hang.
# (See https://github.com/krallin/tini#why-tini).
ENTRYPOINT ["/usr/bin/tini", "--"]

# Documented default mode for this image: MCP over HTTP, HNS resolution via
# the local SPV lane (hnsd, verified) with the shipped DoH fallback list
# (src/network/hns/doh.zig) used only if the SPV sidecar cannot start.
CMD ["/bin/0xroboros-browser", "mcp", "--host", "0.0.0.0", "--port", "9223", "--hns-resolver", "spv", "--hnsd-path", "/bin/hnsd"]
