# Upstream sync policy

This fork tracks [lightpanda-io/browser](https://github.com/lightpanda-io/browser)
(AGPL-3.0-only) and intends to keep tracking it indefinitely. Founder ruling,
2026-08-17: keep the fork and keep syncing upstream — do not rewrite the
engine or let it drift into an unsyncable one-off. This document is the
mechanical policy for how that stays true over time; it does not restate
what changed (that's [`../MODIFICATIONS.md`](../MODIFICATIONS.md)) or the
licensing boundary around the fork (that's
[LICENSE-POSTURE.md](LICENSE-POSTURE.md)).

## Policy

- **We pull, never push upstream.** This fork has no relationship to
  upstream other than reading its `main` branch. No branch, PR, issue, or
  any other write ever targets `lightpanda-io/browser`. `upstream` is
  fetch-only in practice even where git would technically permit a push.
- **`MODIFICATIONS.md` is updated on every sync**, not just on every new
  feature. If a sync pulls in an upstream change to a file this fork also
  touches, the entry for that file in `MODIFICATIONS.md` is re-checked and,
  if the diff's shape changed, re-described. A sync that leaves
  `MODIFICATIONS.md` stale is not finished.
- **Our layer is rebased on top of upstream, not merged sideways into it.**
  The HNS/DANE/SPV/verdict work (Lanes T/D/S/V/G, see `MODIFICATIONS.md`)
  is additive and file-scoped by design specifically so it can be replayed
  on a newer upstream base with minimal conflict surface. A sync that
  reaches for a broad three-way merge instead of a clean rebase is a sign
  the layer has stopped being "thin" per the standing law it was built
  under, and that's worth flagging on its own, not just resolving conflicts
  and moving on.

## Merge-and-verify procedure

1. `git fetch upstream main` (read-only; never assume local state, always
   fetch fresh).
2. Rebase this fork's `main` onto `upstream/main` (or merge, if a rebase
   would rewrite history already pushed and shared — judgment call per
   sync, but rebase is the default and the reason the layer is kept thin).
3. Resolve conflicts favoring our layer **only in files our layer owns or
   touches** (everything named in `MODIFICATIONS.md`, plus new files under
   `src/network/hns/`, `vendor/hnsd/`). Everywhere else, take upstream's
   side — this fork carries no opinion on code it didn't write.
4. Full test suite, unchanged-count discipline: run the repo's existing
   suite per `CONTRIBUTING.md`, and the sync is only clean if the pass/fail
   counts match the pre-sync baseline (module for tests upstream itself
   added or removed — those are expected to move; anything in this fork's
   own files is not).
5. Diff audit on the touched files: confirm the rebase didn't silently pull
   in a change to `ssl_verify`, `insecure_disable_tls_host_verification`,
   or any other TLS-verification default. This fork ships with every TLS
   default upstream ships with, on ICANN names, always — a sync is not the
   place that quietly stops being true.
6. Update `MODIFICATIONS.md` per the policy above.
7. PR against this fork with an explicit `--repo 0xroboros/0xroboros-browser`
   (never rely on the ambient `gh` default repo). Self-review per the
   suspended-Codex-gate discipline; merge only after green `repo-checks`.

## Cadence

- **On every upstream security advisory or tagged release.** These are the
  syncs that matter most and the ones this policy exists to make routine
  rather than exceptional.
- **A light regular check otherwise** — a periodic `git fetch upstream main`
  plus the drift measurement below, on a cadence that catches a stale base
  before it becomes a large one, without treating every upstream commit as
  a trigger. Not every check becomes a sync; a check just answers "is it
  time yet," using the file-overlap signal below to decide.

Drift measurement (read-only, safe to run any time, changes nothing):

```
git fetch upstream main
git log --oneline <pinned-base>..upstream/main | wc -l          # commits behind
git log --name-only --format="" <pinned-base>..upstream/main \
  | sort -u | grep -Ff <(printf '%s\n' \
      $(awk -F'|' '/^\| `/{print $2}' ../MODIFICATIONS.md \
        | tr -d ' `' | sort -u))                                 # overlap with our files
```

The pinned base is the upstream commit `MODIFICATIONS.md` currently records
this fork's layer as cut from. A rising commits-behind count with zero file
overlap is low-urgency (queue it for the next tagged-release sync). Any
overlap with `src/network/hns/*`, `src/sys/libcurl.zig`, `vendor/hnsd/`, or
anything else this fork's layer owns outright is high-urgency regardless of
where it falls in the cadence, because that's exactly the file a sync
conflict would land in.

## Boundaries this policy does not cross

- **The W3 boundary holds through every sync.** This fork's own layer is
  resolution and certificate checking only — never key material, signing,
  wallet RPC, or anything derived from the estate seed — and a sync never
  changes that scope. If a future sync were ever asked to pull in
  something that touches key material, that request is out of policy, full
  stop, regardless of what upstream did.
- **This policy governs code sync only.** It has no bearing on licensing —
  see [LICENSE-POSTURE.md](LICENSE-POSTURE.md) for where proprietary
  0xroboros value sits relative to this AGPL codebase.
