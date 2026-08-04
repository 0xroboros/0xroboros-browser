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

## Lane D — DANE/TLSA for Handshake names (TRUSTED)

DANE-EE(3) validation for HTTPS/WSS to names outside the ICANN root: a leaf
certificate matching a TLSA record (fetched over the same configured DoH
channel) authenticates the connection without a CA; a non-empty set with no
match is a hard failure; an absent set or failed lookup keeps standard CA
validation (fail-closed, no accept-any fallback). STILL TRUSTED end-to-end:
TLSA records are only as strong as the resolver answering; Lane S (hnsd SPV)
upgrades this same path to verified records. ICANN names never enter the
DANE path and their TLS handling is byte-identical to upstream. For an armed
DANE-EE connection the libcurl hostname check is disabled per RFC 7671 §5.1
(the TLSA lookup path is the name binding); every other connection keeps it.

| File | Change |
|---|---|
| `src/network/hns/tlsa.zig` | New: TLSA lookup over the effective DoH endpoint (`_<port>._tcp.<host>`, RFC 6698/7671 subset: usage DANE-EE(3); selectors Cert(0)/SPKI(1); matching Full(0, normalized to SHA-256), SHA-256(1), SHA-512(2)), per-connection `DaneState`, BoringSSL cert-verify callback (SNI-scoped, sets an explicit verify error on mismatch). |
| `src/network/hns/icann_tlds.zig` | New: generated ICANN root TLD list (IANA `tlds-alpha-by-domain.txt`, version 2026080400) — the HNS/ICANN discriminator. |
| `src/network/hns/doh.zig` | Endpoint hardening: fixed default+fallback pair generalized to an ordered candidate list (4 entries, all verified live 2026-08-04) with a one-shot probe walk; first live endpoint wins for the session. |
| `src/network/http.zig` | `Connection`: embedded DANE state; `setURL` arms TLSA for HNS-name TLS URLs (HTTP and websocket transfers both pass through it); the ssl_ctx callback installs the DANE verify callback on armed connections. |
| `src/Config.zig` | `--hns_dane` (`off` supported, default on when the HNS lane is active); accessor `hnsDaneEnabled()`. |
| `src/help.zon` | `--hns-dane` help block. |

DANE-TA(2) does not land cleanly in the existing X509 store flow and is
deliberately out of scope: such records are unusable here, and a set with
nothing usable falls back to standard CA validation.
