# License posture

> **This is an internal position record, not legal advice.** It states how
> 0xroboros treats the boundary between this AGPL-3.0-only codebase and its
> own proprietary work today. It is not a substitute for review by
> qualified counsel, and that review is recommended before any commercial
> distribution that relies on the boundary described here.

Founder ruling, 2026-08-17: proprietary 0xroboros value lives **outside**
the AGPL boundary, handled architecturally — never by relicensing, dual-
licensing, or any attempt to carve out an exception inside this codebase.
This document states that boundary plainly so it stays a design constraint
every future change is checked against, not a one-time decision that erodes
file by file.

## The browser is AGPL-3.0, and stays AGPL-3.0

This fork of [lightpanda-io/browser](https://github.com/lightpanda-io/browser)
is licensed [AGPL-3.0-only](../LICENSE), inherited unchanged from upstream.
Every file this fork adds carries the same license
(see [`../MODIFICATIONS.md`](../MODIFICATIONS.md) for the complete list).
There is no plan, now or later, to relicense the engine, dual-license it, or
ship a proprietary fork of it. The license posture of the browser binary
itself is not the lever 0xroboros uses to protect its own value — the
architecture is.

## The boundary

Proprietary 0xroboros value lives **outside the browser process**, across
one of a small number of explicit boundaries:

- **MCP** — the Model Context Protocol server this fork exposes (`mcp`
  command). A proprietary consumer talks to it as a client, over the wire.
- **CDP** — the Chrome DevTools Protocol surface this fork exposes. Same
  shape: a proprietary consumer drives it as a client, over the wire.
- **Sidecar services** — separate processes (proprietary or not) that this
  fork's binary spawns, attaches to, or is deployed alongside, communicating
  over a socket or local RPC, never a shared address space.

Nothing proprietary is ever **compiled into or statically linked into the
AGPL binary**. If a piece of 0xroboros logic cannot run as a separate
process talking to the browser over MCP, CDP, or an equivalent wire
protocol, it does not belong in this repository, full stop — the fork gains
a feature only when the feature is itself either AGPL-compatible or
upstream-shaped, never when the feature is a container for proprietary
code.

### The pattern already in production: `hns-verdict/1`

The `hns-verdict/1` surface (`docs/hns-agent-verdicts.md`; the MCP `verdict`
tool and the CDP `LP.getHnsVerdict` command; schema in
`src/network/hns/verdict.zig`) is the working example of this boundary, not
a hypothetical:

- The **browser** resolves a name (SPV or DoH), checks DANE/TLSA where
  applicable, and reports what it found — a self-contained, evidence-
  carrying verdict object. This logic is itself AGPL, in this repository,
  and stays there.
- A **proprietary consumer** — anything 0xroboros builds that reads
  `hns-verdict/1` output and acts on it (routing decisions, trust scoring,
  agent policy, billing, anything) — sits entirely on its own side of the
  MCP/CDP wire. It never becomes part of this binary, is never statically
  linked against it, and does not need to be AGPL.

The browser **emits evidence**; proprietary consumers **act on it from
their own side of the boundary**. That split is the whole pattern, and it
generalizes to every future proprietary feature the same way `hns-verdict/1`
does today.

## What this permits

- Building proprietary 0xroboros services — closed-source, unpublished,
  commercial — that consume this browser's MCP or CDP output as a client.
- Deploying this AGPL binary (unmodified, or modified per the AGPL's own
  terms) alongside proprietary sidecars, with a wire protocol between them.
- Distributing or operating this fork commercially, so long as the fork
  itself remains AGPL-compliant (source availability per below) and no
  proprietary code is linked into it.

## What this forbids

- Compiling or statically linking proprietary 0xroboros code into this
  AGPL binary, in any form — a bundled library, a build-time include, a
  vendored dependency that is itself proprietary, or any other mechanism
  that puts proprietary and AGPL code in the same compiled artifact.
- Treating the AGPL boundary as something to route around by keeping
  proprietary logic technically "in a different file" while still
  compiling into the same binary. The test is the compiled artifact, not
  the source layout.
- Relicensing, dual-licensing, or otherwise altering this codebase's own
  license to accommodate proprietary code. If something needs a different
  license to exist, it lives in a different repository, on the other side
  of the wire.

## The AGPL network-use implication

The AGPL-3.0's distinguishing clause (§13) extends the ordinary GPL
source-availability trigger from *distribution* to *network use*:
operating a modified version of this AGPL work as a network-accessible
service, and letting users interact with it remotely, triggers the same
obligation to make that modified version's source available to those
users — even though no copy of the binary was ever handed to them.

What this means in practice for this fork: if 0xroboros modifies this
browser (beyond what's already in `MODIFICATIONS.md`) and runs the
modified version as a service anyone interacts with over a network — the
MCP server, the CDP surface, `serve`, anything — the source of *that
modified AGPL work* must be made available to those users. This obligation
attaches to the AGPL codebase itself, not to whatever proprietary consumer
sits across the MCP/CDP boundary consuming its output; that separation is
exactly why the boundary is architected the way it is. It is not, on its
own, a license position on what a proprietary consumer must disclose about
itself merely for talking to this service over the wire — that question,
like everything else in this document, is a matter for qualified counsel
before it is relied on commercially.

## See also

- [`../MODIFICATIONS.md`](../MODIFICATIONS.md) — the complete, per-file
  diff against upstream, and the license each new file carries.
- [`../LICENSING.md`](../LICENSING.md) — the repository's license
  statement.
- [`../CLA.md`](../CLA.md) — upstream's own contributor agreement,
  inherited unchanged; not authored by or for 0xroboros.
- [UPSTREAM-SYNC.md](UPSTREAM-SYNC.md) — the code-sync policy this
  document's boundary sits alongside; sync policy governs what code enters
  this repository, this document governs what never does.
