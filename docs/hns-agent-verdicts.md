# Agent verdicts for Handshake names (`hns-verdict/1`)

Agents get verdicts, not page bytes. Every Handshake-name resolution and
DANE/TLSA check this fork performs — over MCP or CDP — can be reported as a
signed, versioned `hns-verdict/1` object: what lane resolved the name, what
the DANE outcome was, whether that outcome is chain-anchored, and the
evidence behind it. This page is agent-facing: it shows the object shape and
a complete worked example, not the implementation (see `MODIFICATIONS.md`
"Lane V" for that, and `src/network/hns/verdict.zig` for the source of
truth).

Internal `.0xtestrun` names are used below as the worked example — this is
an internal repo doc; the same names are never used in anything
public-facing.

## Why a verdict, not a page

A page fetch answers "what does this page say." A verdict answers "should an
agent trust the channel it came over, and why." The two are orthogonal:

- **`fetch a page`** (the `goto`/`markdown`/`html` tools, or a normal CDP
  navigation) resolves the name, performs the full DANE-or-CA TLS check, and
  returns content.
- **A verdict** performs the resolve + DANE check *only* — no HTTP request
  goes out (`CURLOPT_CONNECT_ONLY=2` stops the transfer right after the TLS
  handshake) — and returns the outcome plus its evidence. Cheaper than a
  fetch, and the right primitive when an agent needs to decide *whether* to
  act on a name before paying for the page.

A verdict is also attached, additively, to every real fetch: the MCP
`verdict` tool and the CDP `LP.getHnsVerdict` command are the *standalone*
form; `Network.responseReceived` / `Network.loadingFailed` over CDP carry the
same shape as a passive `hnsVerdict` field for names outside the ICANN root.

## The schema

```
schema            "hns-verdict/1"
name              the name checked
resolution_path   "spv" | "doh" | "os"
resolver          { endpoint }              — doh path
                  { sync_height, chain_time } — spv path (hnsd's own local
                                                 chain-status channel)
dane
  outcome         "matched" | "mismatch" | "absent" | "lookup_failed" | "off"
  matched         { usage, selector, matching_type, digest_hex, spki_sha256 }
                  — present only when outcome is "matched"
verified          true only when resolution_path is "spv" AND hnsd itself
                  returned an AD-validated answer. Never true for doh or os.
checked_at        when this verdict was computed (RFC 3339)
evidence
  records_seen    every usable DANE-EE TLSA record the lookup returned
  detail          free-form note: why a lookup failed, that a mismatch
                   blocked a connection, or a stated scope boundary on a
                   passively observed verdict. Never key material.
```

Vocabulary law (binding across this fork, standing since Lane T/D/S):
`verified` means chain-anchored — the spv path, hnsd's own locally-synced
header chain as the trust root. The doh path is TRUSTED, never "verified":
a remote resolver's word, taken as given. `resolution_path` always tells you
which one you got; `verified` never claims more than `resolution_path`
backs.

## Fail-closed inheritance

The verdict surface reports what the DANE engine already decided. It never
overrides it, and it never re-implements the match/mismatch decision
separately from the engine's own path:

- The standalone check (`verdict` tool / `LP.getHnsVerdict`) drives the
  *exact same* `http.Connection` arm/verify path a real fetch uses — same
  TLSA lookup, same BoringSSL cert-verify callback, same fail-closed rule
  (an armed record set with no match hard-fails the handshake). It just
  stops before the HTTP request goes out.
- The passive attachment (`Network.responseReceived` / `.loadingFailed`)
  reads back the `DaneState` an already-completed connection left behind. A
  DANE mismatch that blocked a connection is reported as blocked
  (`dane.outcome: "mismatch"`), with the evidence that blocked it — never
  silently downgraded, never hidden behind a generic error string.

## Worked example: the phase-1 web-a / dane-b pair

`web-a.endpoint.api.0xtestrun` and `dane-b.endpoint.api.0xtestrun` are the
fork's own owned-and-operated proof pair (phase 1 of this program):
`web-a` serves the certificate its published TLSA record actually names;
`dane-b` deliberately serves a certificate that does *not* match its
published TLSA record — a negative control. Both live on the same Fly
listener via SNI, both were driven through the same Lane S SPV path in
phase 2's re-run proof.

Calling the standalone check against each (MCP: `verdict` tool; CDP:
`LP.getHnsVerdict` — identical shape either way) with the spv lane active
produces:

**`web-a` — matched, verified:**

```json
{
  "schema": "hns-verdict/1",
  "name": "web-a.endpoint.api.0xtestrun",
  "resolution_path": "spv",
  "resolver": { "sync_height": 342601, "chain_time": 1786672807 },
  "dane": {
    "outcome": "matched",
    "matched": {
      "usage": 3,
      "selector": 1,
      "matching_type": 1,
      "digest_hex": "17c1f6bd9c1a2e4f7b3d8a5c6e0f2b4d7a9c1e3f5b7d9a1c3e5f7b9d1a3c5e6a",
      "spki_sha256": "17c1f6bd9c1a2e4f7b3d8a5c6e0f2b4d7a9c1e3f5b7d9a1c3e5f7b9d1a3c5e6a"
    }
  },
  "verified": true,
  "checked_at": "2026-08-14T14:03:11Z",
  "evidence": {
    "records_seen": [{
      "rtype": "TLSA",
      "usage": 3,
      "selector": 1,
      "matching_type": 1,
      "digest_hex": "17c1f6bd9c1a2e4f7b3d8a5c6e0f2b4d7a9c1e3f5b7d9a1c3e5f7b9d1a3c5e6a"
    }]
  }
}
```

**`dane-b` — mismatch, blocked (the negative control):**

```json
{
  "schema": "hns-verdict/1",
  "name": "dane-b.endpoint.api.0xtestrun",
  "resolution_path": "spv",
  "resolver": { "sync_height": 342601, "chain_time": 1786672807 },
  "dane": { "outcome": "mismatch" },
  "verified": true,
  "checked_at": "2026-08-14T14:03:12Z",
  "evidence": {
    "records_seen": [{
      "rtype": "TLSA",
      "usage": 3,
      "selector": 1,
      "matching_type": 1,
      "digest_hex": "24f45b245653c9514f9ff3a46129c78179763b95a353a9c06c3d35fed44803a"
    }],
    "detail": "connection blocked: served certificate matched no TLSA record"
  }
}
```

`dane-b` serves K1's certificate but publishes K2's SPKI SHA-256 as the
TLSA record (deliberate, phase 1's negative control): `evidence.records_seen`
shows exactly what was published; `dane.matched` stays absent because
nothing matched; `verified: true` because the *lookup itself* was
chain-validated over the spv path — hnsd answered honestly that this is what
the chain publishes, even though the served certificate doesn't honor it.
`verified` describes the lookup's trust anchor, not the connection's
outcome.

The illustrative fingerprints and heights above show the object shape; treat
the live values in `0xos/endpoint-api/docs/2026-08-14_0xroboros_web-a-dane-proof-runbook_v02.md`
and this fork's own phase 1/2 result records as the source of truth for the
exact bytes on any given day (position keys and the chain tip both move).

## Calling it

**MCP** (`verdict` tool):

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"verdict","arguments":{"name":"web-a.endpoint.api.0xtestrun"}}}
```

**CDP** (`LP.getHnsVerdict`):

```json
{"id":1,"method":"LP.getHnsVerdict","params":{"name":"web-a.endpoint.api.0xtestrun"}}
```

Both accept an optional `port` (default `443`). Both return the identical
`hns-verdict/1` shape — the schema is the contract, not the transport.

## Open items for MVP integration

- The passive CDP attachment (`fromObservedConnection`) cannot distinguish a
  failed TLSA lookup from a confirmed-empty one — both leave a completed
  connection's `DaneState` unarmed identically. It reports `absent` with an
  `evidence.detail` note saying so. Use the active check (`verdict` tool /
  `LP.getHnsVerdict`) when that distinction matters.
- `matched` reports the first usable TLSA record in the set. Real
  `.0xtestrun` positions currently mint a single record per name, so this is
  exact today; a genuinely multi-record RRset would need the engine's own
  match index threaded back out to report *which* record matched — not
  wired yet.
- `resolver.sync_height` / `chain_time` come from hnsd's own local Hesiod
  status channel (`height.tip.chain.hnsd.` / `time.tip.chain.hnsd.`,
  `vendor/hnsd/src/hesiod.c`) — a receipt pointing at the locally-synced
  header chain, not a re-derivation of the SPV proof itself. Fine for an
  agent's evidence trail; not a substitute for an actual chain-proof export
  if the MVP integration ever needs one.
