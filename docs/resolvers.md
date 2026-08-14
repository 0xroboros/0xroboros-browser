# Handshake resolution: lanes, endpoints, fallback

This fork resolves names outside the ICANN root (Handshake/HNS names)
through one of two lanes, selected by `--hns-resolver <spv|doh|off>`
(default `spv` when the HNS lane is active). Both are documented in full in
`lightpanda <serve|fetch|mcp|agent> --help` under the `--hns-*` /
`--hnsd-path` options; this page is the endpoint-list and fallback-behavior
reference the CLI help intentionally keeps short.

## TRUSTED vs verified — the vocabulary law

This fork uses the two words to mean specific, different things, and never
mixes them:

- **`verified`**: the SPV lane (`--hns-resolver=spv`, the default). A local
  `hnsd` sidecar syncs Handshake's header chain itself and validates every
  answer against it — the trust root is the chain, not a party's word.
- **TRUSTED, never "verified"**: the DoH lane (`--hns-resolver=doh`, or an
  automatic fallback from a failed SPV startup). A remote DNS-over-HTTPS
  resolver answers the query; its answer is taken as given, over TLS to the
  resolver, with no chain validation on this client's side.

Every `hns-verdict/1` object (see [hns-agent-verdicts.md](hns-agent-verdicts.md))
and every startup/fallback log line states which of the two applies. A
result never claims `verified` unless the SPV lane produced it.

## SPV lane (`--hns-resolver=spv`, verified)

Attaches to a local `hnsd` daemon (auto-spawned via `--hnsd-path`, default
search: `vendor/hnsd/hnsd` repo-relative, then `PATH`, then common install
locations — the OCI image ships a prebuilt one at `/bin/hnsd`) or a
`HOST:PORT` given to `--hns-spv`. `hnsd` syncs Handshake's header chain
itself (P2P, no trusted party) and answers both name resolution and TLSA
lookups (for `--hns-dane`) from that locally-validated chain state.

If SPV startup fails (no peers reachable, sidecar binary not found, etc.)
this fork logs a loud warning and downgrades to the DoH lane for the
session — it does not fail closed to "no HNS resolution," and it does not
silently claim `verified` for what became a TRUSTED answer:

```
hns spv startup failed, downgrading to TRUSTED doh for this session
```

## DoH lane (`--hns-resolver=doh`, or the SPV-failure fallback; TRUSTED)

Four public community endpoints, probed once at startup, top to bottom;
the first live one wins for the whole session (no background health
checks, no runtime re-ranking):

| Rank | Endpoint | Operator |
|---|---|---|
| 0 (default) | `https://hnsdoh.com/dns-query` | [hns_doh_loadbalancer](https://github.com/nathanwoodburn/hns_doh_loadbalancer), community, multi-node |
| 1 | `https://dns.easyhns.com/dns-query` | [Easy HNS](https://easyhns.com), independent operator |
| 2 | `https://eu.hnsdoh.com/dns-query` | Direct regional node behind rank 0's balancer |
| 3 | `https://au.hnsdoh.com/dns-query` | Direct regional node behind rank 0's balancer |

All four verified live 2026-08-04 (see `MODIFICATIONS.md` "Lane T"). An
explicit `--hns-doh-url <URL>` skips this list entirely and pins one
endpoint (or disables the lane with `--hns-doh-url off`). If every probe
misses, the client settles on rank 0 and lets resolution fail loudly rather
than silently falling back to plain OS resolution.

`--hns-resolver=off` is the master switch: no HNS resolution at all,
regardless of any other `--hns-*` flag — Handshake names then resolve the
same way they would on an unmodified upstream client (`CouldntResolveHost`
outside a Handshake-aware network setup).

## Trying it against a real, public Handshake name

`nathan.woodburn` is a real, independently-operated Handshake name this
fork's own DoH startup probe already queries (see
`src/network/hns/doh.zig`) — a convenient live target that isn't this
fork's own infrastructure:

```sh
lightpanda fetch --dump markdown https://nathan.woodburn/
```
