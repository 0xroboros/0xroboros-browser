# Agent verdicts for Handshake names (`hns-verdict/1`)

Agents get verdicts, not page bytes. Every Handshake-name resolution and
DANE/TLSA check this fork performs — over MCP or CDP — can be reported as a
signed, versioned `hns-verdict/1` object: what lane resolved the name, what
the DANE outcome was, whether that outcome is chain-anchored, and the
evidence behind it. This page is agent-facing: it shows the object shape and
a complete worked example, not the implementation (see `MODIFICATIONS.md`
"Lane V" for that, and `src/network/hns/verdict.zig` for the source of
truth).

This is a public-repo doc: the worked example below uses placeholder names
(`service.example` / `mismatch.example`) with illustrative byte values, not
a real, resolvable Handshake position. For a live call against a real
public Handshake name, see [quickstart.md](quickstart.md).

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

## Worked example: a matched pair and a negative control

`service.example` and `mismatch.example` below are placeholder names
illustrating the object shape, not resolvable Handshake positions: imagine
two names, each with a TLSA record published on Handshake — `service.example`
serves the certificate its record actually names; `mismatch.example`
deliberately serves a certificate that does *not* match its published TLSA
record (a negative control, useful for testing that a client fails closed
on a DANE mismatch rather than falling back to CA validation). For a live
call against a real public Handshake name, see [quickstart.md](quickstart.md)
— most public names will report `dane.outcome: "absent"` (no TLSA record
published), which is a normal, successful lookup, not an error.

Calling the standalone check against each (MCP: `verdict` tool; CDP:
`LP.getHnsVerdict` — identical shape either way) with the spv lane active
produces:

**`service.example` — matched, verified:**

```json
{
  "schema": "hns-verdict/1",
  "name": "service.example",
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

**`mismatch.example` — mismatch, blocked (the negative control):**

```json
{
  "schema": "hns-verdict/1",
  "name": "mismatch.example",
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

`mismatch.example` serves one certificate but publishes a *different* key's
SPKI SHA-256 as its TLSA record: `evidence.records_seen` shows exactly what
was published; `dane.matched` stays absent because nothing matched;
`verified: true` because the *lookup itself* was chain-validated over the
spv path — hnsd answered honestly that this is what the chain publishes,
even though the served certificate doesn't honor it. `verified` describes
the lookup's trust anchor, not the connection's outcome.

The fingerprints and heights above are illustrative values showing the
object shape, not a live capture — the exact bytes on any real name shift
with that name's own key and the current chain tip.

## Calling it

**MCP** (`verdict` tool):

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"verdict","arguments":{"name":"nathan.woodburn"}}}
```

**CDP** (`LP.getHnsVerdict`):

```json
{"id":1,"method":"LP.getHnsVerdict","params":{"name":"nathan.woodburn"}}
```

Both accept an optional `port` (default `443`). Both return the identical
`hns-verdict/1` shape — the schema is the contract, not the transport.

## Open items for MVP integration

- The passive CDP attachment (`fromObservedConnection`) cannot distinguish a
  failed TLSA lookup from a confirmed-empty one — both leave a completed
  connection's `DaneState` unarmed identically. It reports `absent` with an
  `evidence.detail` note saying so. Use the active check (`verdict` tool /
  `LP.getHnsVerdict`) when that distinction matters.
- `matched` reports the first usable TLSA record in the set. Names that
  publish a single TLSA record are exact today; a genuinely multi-record
  RRset would need the engine's own match index threaded back out to report
  *which* record matched — not wired yet.
- `resolver.sync_height` / `chain_time` come from hnsd's own local Hesiod
  status channel (`height.tip.chain.hnsd.` / `time.tip.chain.hnsd.`,
  `vendor/hnsd/src/hesiod.c`) — a receipt pointing at the locally-synced
  header chain, not a re-derivation of the SPV proof itself. Fine for an
  agent's evidence trail; not a substitute for an actual chain-proof export
  if the MVP integration ever needs one.
