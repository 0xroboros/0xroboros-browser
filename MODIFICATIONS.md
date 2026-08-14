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

## Lane S — VERIFIED resolution via a local hnsd SPV daemon

The terminal lane: [hnsd](https://github.com/handshake-org/hnsd) (MIT) syncs
Handshake block headers peer-to-peer, derives the name root committed on
chain, and serves a validating resolver on localhost. When this lane is
active, Handshake names resolve through it (AD required — answers validated
against the chain, not any remote resolver), TLSA records for the Lane D
DANE check arrive over the same verified channel, the trusted DoH lane is
not selected (it remains the automatic startup fallback), and ICANN names
use plain OS resolution, byte-identical to upstream.

Fail-closed: an hnsd lookup that fails or comes back unvalidated is a
resolution failure for that name — never a silent downgrade to a trusted
channel mid-session. Lane selection happens once, at startup, and is logged.

| File | Change |
|---|---|
| `vendor/hnsd/` | New: vendored hnsd source, pinned commit (MIT; see `vendor/hnsd/VENDORED_COMMIT` and "chain-compat" below). Not part of the default build. |
| `build.zig` | New `hnsd` step (`zig build hnsd`): autotools bootstrap (`autogen.sh` → `configure` → `make`) against `vendor/hnsd`, installs to `zig-out/bin/hnsd` and `vendor/hnsd/hnsd`. Off the default build (needs autoconf/automake/libtool/pkg-config + libunbound; see "chain-compat" below for the environments this has been proven against). |
| `src/network/hns/spv.zig` | New: lane selection (`auto` attaches to a running daemon on 127.0.0.1:15353 or spawns the hnsd sidecar; `off`; `host:port` attaches), UDP DNS client with AD enforcement, sidecar lifecycle (spawn with the real process environ, SIGKILL reap — the browser's signal mask is inherited by the child, so blockable signals never arrive), first-run sync grace window. `auto` binary search checks `vendor/hnsd/hnsd` first (repo-relative), then PATH, then the usual install locations. Startup failure (no reachable daemon, sidecar spawn/ready timeout) logs a `.warn`-level line naming the downgrade to TRUSTED doh, not `.info`. |
| `src/network/hns/tlsa.zig` | Wire helpers generalized (`buildQuery` takes a qtype, root qname handled, `parseTlsa`/`skipName` pub); `DaneState.verified` distinguishes the SPV channel from the DoH channel in logs. |
| `src/network/hns/doh.zig` | `select`: `--hns-resolver=off` is checked first and disables this lane outright, regardless of `--hns-doh-url`. |
| `src/network/http.zig` | `setURL`: SPV-resolved addresses pinned per handle via `CURLOPT_RESOLVE`; TLSA sourced from hnsd when SPV is active; DANE gate includes the SPV lane. |
| `src/sys/libcurl.zig` | `CurlOption`: `resolve = CURLOPT_RESOLVE` (slist). |
| `src/network/Network.zig` | Lane selection order: SPV first, DoH only when SPV is unavailable; sidecar shutdown on deinit. |
| `src/Config.zig` | `--hns-resolver <spv\|doh\|off>` (new; default spv when the HNS lane is active — the master selector, see below), `--hns_spv <auto\|off\|host:port>` (default auto), `--hnsd_path`; accessors. |
| `src/help.zon` | `--hns-resolver`, `--hns-spv`, and `--hnsd-path` help blocks (re-sorted alphabetically into the existing `--hns-*` run, which had drifted out of order). |

Precedence: **`--hns-resolver` is the master switch** (item 3 of the Lane S
program). `spv` (default): SPV first; on startup failure (no peers, sync
failure, no binary found) resolution falls back to the doh lane for the
rest of the session, with a `.warn`-level log line naming the downgrade to
TRUSTED. `doh`: the doh lane only, SPV never attempted. `off`: plain OS
resolution, unchanged — confirmed by fetching an HNS name under `off`,
which fails with `CouldntResolveHost` exactly as it would upstream.
`--hns-spv` and `--hns-doh-url` remain available underneath whichever lane
`--hns-resolver` selects, for finer control (attach to a specific spv
daemon or host:port; pin a specific DoH endpoint); an explicit
`--hns-doh-url` (URL or `off`) is still also, on its own, a user choice of
the doh lane or of no HNS resolution, and disables SPV. With SPV active the
program's trust vocabulary upgrades: resolution and DANE records are
VERIFIED (chain-anchored), not merely trusted.

### Lane S — chain-compat (vendored hnsd)

hnsd is vendored at `vendor/hnsd/` rather than merely required at runtime:
pinned commit, exact provenance, and chain-compat notes are in
`vendor/hnsd/VENDORED_COMMIT`. Summary: the last tagged release is v2.0.0;
the pinned commit is 13 untagged commits ahead of it on `master` (the
binary still self-reports `2.99.0`), including an ICANN-domain resolution
fix (`8dccc02`) this fork wants. No local patches — pristine
`git archive` of the pinned commit; `LICENSE` (MIT) carried alongside it.

"Stale, needs the build-against-current-chain treatment" (item 1) means:
prove this exact pinned commit still syncs and validates against *current*
mainnet consensus, not the chain as it stood near v2.0.0. Measured, this
session, against live Handshake mainnet (chain tip height 342601 as of
2026-08-14, this fork's own build via `zig build hnsd` / `make hnsd`, arm64
macOS, home network — not a lab benchmark):

- **Cold sync** (empty `-x` prefix directory, no `-t` hard-coded-checkpoint
  flag — the exact invocation shape `src/network/hns/spv.zig`'s sidecar
  spawn uses in production, genesis-to-tip via P2P, no shortcuts): the
  daemon's own `chain is fully synced` log line landed before the 166-second
  mark; a live AD-validated query (`nathan.woodburn` A, answered from the
  chain-derived root, RRSIG present) succeeded by the 215-second mark, at
  which point it was reaping headers/blocks for the current tip (342601) in
  real time. Call it **under 4 minutes** cold, on this connection, to a
  fully operational validating resolver — not the many-hour worst case a
  1.5M+-header genesis walk might suggest; Handshake's actual chain height
  at this point in 2026 keeps a from-scratch P2P sync inside single-digit
  minutes.
- **Warm resume** (a day-old on-disk checkpoint from a prior run, ordinary
  `--hns-spv=auto` production path): `chain is fully synced` inside 48
  seconds, cold process start to warm.
- **Steady-state memory**: RSS settled at **8.1–8.4 MB** (`ps -o rss=`,
  sampled repeatedly post-sync) while serving live validated queries. This
  is consistent with, and slightly under, hnsd's own published figure —
  "about 12mb of memory when operating with a full DNS cache" (`vendor/hnsd/README.md`,
  [handshake-org/hnsd](https://github.com/handshake-org/hnsd)) — which is
  cited here rather than re-derived; the 8.1–8.4 MB reading is this
  session's own measurement on the pinned commit, not a substitute for it.

Verified functional, not just numerically: both figures above were taken
against a daemon actually serving AD-validated live-mainnet answers
end-to-end (see "Verification" in the phase result), including the
re-run Lane-S proof pair (`web-a`/`dane-b` under `.0xtestrun`, a real owned
Handshake TLD, not a lab fixture).

## Lane V — agent verdict surface

Resolution and DANE outcomes as a first-class, evidence-carrying result —
`hns-verdict/1` — instead of raw page bytes: the machine-economy unlock,
agents operating on Handshake with a portable trust verdict over both the
MCP and CDP surfaces. This surface only *observes and reports* what Lane
S/D/T already decided; it never re-implements the DANE match/mismatch
decision (fail-closed inheritance) and never carries key material.

Vocabulary law extended: `verified` on a verdict is true only for the spv
resolution path, and only when hnsd itself returned an AD-validated answer
(an armed match/mismatch, or a validated-empty absent). A doh-path or
os-path verdict (ICANN names, or a Handshake-shaped name with neither lane
active) is never `verified`.

| File | Change |
|---|---|
| `src/network/hns/verdict.zig` | New: the `hns-verdict/1` schema (`Verdict`, `ResolutionPath`, `DaneOutcome`, `ResolverDetail`, `MatchedRecord`, `Evidence`), `compute` (the "resolve + TLSA check only" primitive — drives the exact same `http.Connection` arm/verify path a real fetch uses, via `CURLOPT_CONNECT_ONLY=2`, stopped after the TLS handshake and before any HTTP request), `fromObservedConnection` (CDP passive-observation path, from an already-completed connection's `DaneState`), `fromBlockedConnection` (a DANE mismatch that blocked a connection), `resolutionPathFor` (pure lane classifier). Schema pin, one test per dane outcome, and the spv-vs-doh `verified` distinction all run as pure unit tests against the builder, no live hnsd/DoH endpoint required. |
| `src/network/hns/tlsa.zig` | `buildQuery` generalized to `buildQueryClass` (adds a DNS class parameter; `buildQuery` is now a thin IN-class wrapper — existing callers unaffected); new `LookupOutcome` union (`failed`/`empty`/`armed(n)`) and `lookupDetailed`, distinguishing a failed lookup from a confirmed-absent TLSA set — `lookup` (the engine's own u8-returning API, used by `http.zig`) is now a thin wrapper over it, behavior unchanged. |
| `src/network/hns/spv.zig` | `query`'s socket send/receive extracted into a shared `sendRecv`; new `queryHesiod` (class HS) and `chainStatus` reading hnsd's own local status channel (`vendor/hnsd/src/hesiod.c`: `height.tip.chain.hnsd.` / `time.tip.chain.hnsd.` TXT records) — the spv-path "resolver detail" and evidence.proof reference in a verdict; new `lookupTlsaDetailed` (same `LookupOutcome` split as tlsa.zig); `lookupTlsa` is now a thin wrapper over it, behavior unchanged. |
| `src/network/HttpClient.zig` | `Transfer` gains `_dane: hns_tlsa.DaneState = .{}`, a snapshot captured in `materializeResponse` (success path) and in the failure branch of `processOneMessage` (before the conn is released and reused, which would otherwise reset it) — read by the CDP attachment below. Pure observation; no change to connection/transfer behavior. |
| `src/cdp/domains/network.zig` | `ResponseWriter` gains a `network: *const Network` field (threaded from `httpResponseHeaderDone`, which already has `bc` in scope) and an additive `hnsVerdict` field on `Network.responseReceived`'s `response` object, present only for names outside the ICANN root (`hnsHostFromUrl`/`isHnsName`) — absent entirely, byte-identical to upstream, for every other response. `httpRequestFail` gains the same additive `hnsVerdict` field on `Network.loadingFailed`, populated only when the failure was `error.PeerFailedVerification` on an HNS name — fail-closed inheritance: a mismatch that blocked a connection is reported as blocked, with the evidence. |
| `src/cdp/domains/lp.zig` | New `LP.getHnsVerdict` command (`{name, port?}` -> a full verdict object) — the CDP-surface counterpart to the MCP `verdict` tool, same `verdict.compute` primitive underneath. |
| `src/mcp/tools.zig` | New `verdict` tool (`{name, port?}` -> a full verdict object as text content) alongside `save`/`session_*`, following the same `ExtraTool` dispatch convention; `tools/list` advertises it. |
| `docs/hns-agent-verdicts.md` | New: agent-facing page showing a complete verdict for a real fetch, using the phase 1 web-a/dane-b pair as the worked example. |

Scope boundary, stated rather than hidden: `fromObservedConnection` (the CDP
passive path) cannot distinguish a failed TLSA lookup from a confirmed-empty
one — both leave a completed connection's `DaneState` unarmed the same way.
It reports `absent` with an `evidence.detail` note saying so. The active
`compute` path (MCP tool / `LP.getHnsVerdict`) does not have this limitation
— it runs the TLSA lookup itself and can tell `lookup_failed` from `absent`
directly.

## Lane S — MVP integration fixes (phase 4)

Two defects surfaced by driving the `verdict` MCP tool against live
`.0xtestrun` positions (phase 4 of the browser program, MVP integration
proof) and fixed here, both additive/surgical to `src/network/hns/spv.zig`:

1. **TLSA lookups had no sidecar-warmup grace window.** `resolve` (A/AAAA)
   already retries up to 30×500ms for a sidecar this process just spawned,
   with the comment "give the first resolutions a grace window instead of
   failing page one of the session." `lookupTlsaDetailed` had no equivalent
   — reproduced directly: a `verdict` check fired immediately after the "hns
   spv sidecar ready" log line failed in under a millisecond
   (`lookup_failed`, "TLSA lookup did not complete cleanly"), while the
   identical check ~20s later, same session, succeeded (`hns dane armed`).
   `lookupTlsaDetailed` now takes the same grace window, keyed off the same
   `resolved_once` state `resolve` already tracks (retries only on
   `.failed`; a validated `.empty` is a real chain-confirmed absence and is
   never retried).
2. **`resolver.sync_height`/`chain_time` were never populated.** `chainStatus`
   queried hnsd's Hesiod status channel (`height.tip.chain.hnsd.` /
   `time.tip.chain.hnsd.`, class HS) on the same port as the recursive
   resolver (`addr`, `-r 127.0.0.1:15353`). Confirmed directly with `dig`
   against a manually-launched sidecar: `dig @127.0.0.1 -p 15353 HS TXT
   height.tip.chain.hnsd` returns `REFUSED` — hnsd runs the Hesiod status API
   on its **root-nameserver** listener, a second, separate port from the
   recursive resolver (`vendor/hnsd/docs/hesiod.md`; confirmed live:
   `dig @127.0.0.1 -p 5349 HS TXT height.tip.chain.hnsd` answered
   `"342607"`, the real chain tip, once pointed at the right port). The
   sidecar spawn now also pins `-n 127.0.0.1:15349` (off the beaten path,
   like the existing `-r` port choice, rather than hnsd's own mainnet
   default 5349, to avoid colliding with an unrelated hnsd a user might
   already have running) and `queryHesiod` targets that address instead of
   the shared recursive-resolver `addr`. Scoped to the sidecar THIS process
   spawns — an attached, externally-run daemon's Hesiod port is unknown to
   us and not guessed at; `chainStatus`/`queryHesiod` degrade to their
   existing null result in that case, same as before this port was known.

| File | Change |
|---|---|
| `src/network/hns/spv.zig` | `lookupTlsaDetailed` split into a retrying wrapper (30×500ms grace window when `child != null and !resolved_once`, mirroring `resolve`) plus `lookupTlsaOnce` (the prior body, unchanged). New `hesiod_port` constant (15349) and `hesiod_addr: ?sys_net.IpAddress` module var, set when `spawn` succeeds (only for a sidecar this process spawned); `spawn`'s argv gains `-n 127.0.0.1:15349`; `shutdown` clears `hesiod_addr` alongside `child`. `sendRecv` takes an explicit target address (`addr` for `query`, `hesiod_addr` for `queryHesiod`) instead of always using the shared recursive-resolver `addr`; `queryHesiod` returns `null` immediately when `hesiod_addr` is unset (attached-daemon case, unchanged behavior). |

Both are additive/surgical: no change to ICANN resolution, DANE match/mismatch
semantics, or any existing passing behavior — confirmed by the full test
suite staying green (see the phase 4 result record) and by an ICANN
regression grep on the diff (`ssl_verify|insecure|verify_host|CURLOPT_SSL`:
zero hits).
