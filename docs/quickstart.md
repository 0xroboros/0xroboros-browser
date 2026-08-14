# Quickstart

Two calls: one plain HNS fetch (proves resolution works), one `hns-verdict/1`
call (proves the agent-facing trust surface works). Both against
`nathan.woodburn`, a real, independently-operated Handshake name — not this
fork's own infrastructure. See [install.md](install.md) for getting the
binary or image, and [resolvers.md](resolvers.md) for what "TRUSTED" vs
"verified" mean below.

## 1. One HNS fetch

```sh
lightpanda fetch --dump markdown https://nathan.woodburn/
```

With the default `--hns-resolver=spv`, the first line of stderr shows the
lane and its trust level:

```
hns spv enabled trust="verified, local spv chain"
```

(If no local SPV sidecar is reachable — no `--hnsd-path` binary, no peers —
this fork logs a loud warning and falls back to the TRUSTED DoH lane for
the session rather than failing the fetch; see resolvers.md.)

## 2. One verdict call

A verdict is the resolve-plus-DANE-check-only primitive — no page fetch, no
HTTP request goes out — and the primitive both the MCP `verdict` tool and
the CDP `LP.getHnsVerdict` command wrap. Full schema and a worked example:
[hns-agent-verdicts.md](hns-agent-verdicts.md).

Start the MCP server over HTTP (matches the OCI image's default `CMD`):

```sh
lightpanda mcp --host 0.0.0.0 --port 9223 --hns-resolver spv
```

Session routing follows the `Mcp-Session-Id` header (`src/mcp/HttpServer.zig`):
an `initialize` call without one mints a fresh session and returns its id in
the response header; every later call in that session reuses it. Two calls:

```sh
# 1. initialize — capture the minted Mcp-Session-Id from the response headers
SID=$(curl -si http://localhost:9223/mcp \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"quickstart","version":"1.0.0"}}}' \
  | grep -i '^mcp-session-id:' | tr -d '\r' | cut -d' ' -f2)

# 2. call the verdict tool, in that session
curl -s http://localhost:9223/mcp \
  -H 'content-type: application/json' \
  -H "mcp-session-id: $SID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"verdict","arguments":{"name":"nathan.woodburn"}}}'
```

The response is one `hns-verdict/1` object: `resolution_path` ("spv" or
"doh"), the DANE `outcome` (most public names will report `absent` — no
TLSA record published — which is a normal, successful lookup, not an
error), and `verified` (`true` only for a chain-anchored spv-path result).
`nathan.woodburn` is used here for a live, independent resolution target;
it is not claimed to publish a TLSA/DANE record, so `dane.outcome` on it is
expected to read `absent`, not `matched`.

## Next

- [install.md](install.md) — image, binaries, building from source.
- [resolvers.md](resolvers.md) — the full DoH endpoint list, fallback
  behavior, and the TRUSTED-vs-verified vocabulary.
- [hns-agent-verdicts.md](hns-agent-verdicts.md) — the full `hns-verdict/1`
  schema, the MCP/CDP surfaces, and a DANE-matched worked example.
- `lightpanda <command> --help` for every flag (`serve`, `fetch`, `mcp`,
  `agent`, `run`).
