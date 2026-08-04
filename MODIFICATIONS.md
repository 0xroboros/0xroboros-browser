# MODIFICATIONS

This fork of [lightpanda-io/browser](https://github.com/lightpanda-io/browser)
(AGPL-3.0-only) adds native Handshake (HNS) name resolution. Upstream license
headers are intact; new files carry the same AGPL-3.0 license.

Branch `hns-lane-t` is cut from upstream `main` at commit
`e143533987ca380febf5692fb8113c26e49f1759` (2026-08-03).

## Lane T — Handshake resolution via DNS-over-HTTPS (TRUSTED)

TRUSTED resolution: names are resolved by a remote DoH resolver the user does
not verify. No TLS default is weakened; HTTPS to Handshake names failing CA
validation stays failing. Interim by design: at Lane S kickoff, local SPV
verification (hnsd) becomes the default resolution path and DoH drops to
fallback.

| File | Change |
|---|---|
| `build.zig` | `.CURL_DISABLE_DOH` flipped `true` → `false` (curl's `doh.c` was already compiled). |
| `src/sys/libcurl.zig` | `CurlOption`: added `doh_url = c.CURLOPT_DOH_URL`. |
| `src/Config.zig` | Common option `--hns_doh_url` (serve/fetch/mcp/agent): explicit DoH URL, or `off` to disable HNS resolution; accessor `hnsDohUrl()`. |
| `src/network/hns/doh.zig` | New: default/fallback public endpoint constants, one-shot startup selection with probe-and-fallback, `effectiveUrl()`. |
| `src/network/http.zig` | `Connection.reset`: apply `.doh_url` when an effective URL is selected. Covers HTTP and websocket transfers (both use `Connection`). |
| `src/network/Network.zig` | `Network.init`: call `hns_doh.select(...)` once before the connection pool is built. |

Default endpoint: `https://hnsdoh.com/dns-query` (public community resolver,
[hns_doh_loadbalancer](https://github.com/nathanwoodburn/hns_doh_loadbalancer)).
Automatic session fallback: `https://dns.easyhns.com/dns-query`
([Easy HNS](https://easyhns.com), independent operator). Both verified live
2026-08-04. An own-infrastructure DoH endpoint can be used by setting
`--hns_doh_url` explicitly; it is never the default.
