# Install

This fork adds native Handshake (HNS) name resolution and DANE/TLSA
authentication to [lightpanda-io/browser](https://github.com/lightpanda-io/browser)
(AGPL-3.0-only). It is a community fork; it is not affiliated with,
endorsed by, or published by Lightpanda / Selecy SAS. See
[MODIFICATIONS.md](../MODIFICATIONS.md) for the complete, per-file diff
against upstream, and [`../LICENSE`](../LICENSE) for the license.

Two ways to run it: the OCI image (fastest way to try the agent surface),
or a platform binary.

## OCI image

Multi-arch (`linux/amd64`, `linux/arm64`), published to GHCR on every
tagged release:

```sh
docker pull ghcr.io/0xroboros/0xroboros-browser:latest
# or pin an exact release:
docker pull ghcr.io/0xroboros/0xroboros-browser:vX.Y.Z
```

Default command (see [`../Dockerfile`](../Dockerfile)): starts the MCP
server over HTTP on port 9223, HNS resolution on via the local SPV lane
(hnsd), with the shipped DoH fallback list active only if the SPV sidecar
cannot start (see [resolvers.md](resolvers.md)).

```sh
docker run --rm -p 9223:9223 ghcr.io/0xroboros/0xroboros-browser:latest
```

An agent (or `curl`) can now POST JSON-RPC to `http://localhost:9223/mcp`.
See [quickstart.md](quickstart.md) for a first call.

Every flag documented below (`docker run ... /bin/0xroboros-browser mcp --help`
inside the container, or `lightpanda mcp --help` on a binary) also applies
inside the image — override the image's default `CMD` to change them, e.g.
to run over stdio instead:

```sh
docker run --rm -i --entrypoint /bin/0xroboros-browser \
  ghcr.io/0xroboros/0xroboros-browser:latest mcp
```

## Platform binaries

Published on the [GitHub Releases page](https://github.com/0xroboros/0xroboros-browser/releases)
for `linux/amd64`, `linux/arm64`, and `macos/arm64`, each with a `.sha256`
checksum file alongside it:

```sh
curl -LO https://github.com/0xroboros/0xroboros-browser/releases/download/vX.Y.Z/lightpanda-<arch>-<os>
curl -LO https://github.com/0xroboros/0xroboros-browser/releases/download/vX.Y.Z/lightpanda-<arch>-<os>.sha256
shasum -a 256 -c lightpanda-<arch>-<os>.sha256
chmod +x lightpanda-<arch>-<os>
./lightpanda-<arch>-<os> --help
```

Binary substitutions: `<arch>` is `x86_64` or `aarch64`; `<os>` is `linux`
or `macos`.

The binary does not bundle the hnsd SPV sidecar (`--hns-spv`/
`--hns-resolver=spv` needs it). Either build it from this repo
(`zig build hnsd`, needs `autoconf`/`automake`/`libtool`/`pkg-config` +
`libunbound` — see [`../vendor/hnsd/README.md`](../vendor/hnsd/README.md)),
or run without it: `--hns-resolver=doh` uses the TRUSTED DoH lane directly
with no sidecar, and `--hns-resolver=off` disables HNS resolution entirely.
The OCI image ships hnsd already built in, which is the simpler path if a
prebuilt sidecar is all that's needed.

## Building from source

```sh
git clone https://github.com/0xroboros/0xroboros-browser.git
cd 0xroboros-browser
make build          # lightpanda binary at zig-out/bin/0xroboros-browser
make hnsd           # optional: the vendored SPV sidecar, needs autotools + libunbound
make test           # full test suite
```

See [`../CONTRIBUTING.md`](../CONTRIBUTING.md) for the full dev setup.

## Verifying what you're running

Every image and binary is built directly from a tagged commit of
[`0xroboros/0xroboros-browser`](https://github.com/0xroboros/0xroboros-browser)
— the public source for exactly what is shipped, including every AGPL
modification (see [`../MODIFICATIONS.md`](../MODIFICATIONS.md)). The image
carries this pointer as an OCI label (`org.opencontainers.image.source`,
`docker inspect ghcr.io/0xroboros/0xroboros-browser:latest`).
