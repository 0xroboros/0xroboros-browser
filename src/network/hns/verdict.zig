// Copyright (C) 2026  0xroboros fork of Lightpanda (Selecy SAS)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Agent verdict surface (Lane V): resolution and DANE outcomes as a
// first-class, evidence-carrying result — `hns-verdict/1` — instead of raw
// page bytes. Agents operating on Handshake names get a portable trust
// verdict over both the MCP surface (src/mcp/tools.zig, the `verdict` tool)
// and the CDP surface (src/cdp/domains/lp.zig `LP.getHnsVerdict`, and an
// additive field on `Network.responseReceived` / `Network.loadingFailed`,
// src/cdp/domains/network.zig).
//
// Fail-closed inheritance (standing law, item 4 of the phase 3 brief): this
// module only *observes and reports* what Lane S/D/T already decided. It
// never re-implements the DANE match/mismatch decision — `compute` drives
// the exact same `http.Connection` arm/verify path the real fetch engine
// uses (src/network/http.zig), and `fromObservedConnection` reads back the
// `hns_tlsa.DaneState` an actual completed connection already left behind.
// A mismatch that blocked a connection is reported as blocked, with the
// evidence that blocked it — never silently downgraded or hidden.
//
// Vocabulary law (standing law, item 3 of the phase 1 brief): `verified`
// is true only for the spv resolution path, and only when hnsd itself
// returned an AD-validated answer (armed match/mismatch, or a validated
// empty answer). A doh-path or os-path (plain OS resolution, including
// ICANN names and the case where neither Handshake lane is active) verdict
// is never "verified" — at most "trusted" is implied by the doh label
// itself; this schema never spells that word out because the distinction
// is already carried by `resolution_path`.

const std = @import("std");
const lp = @import("lightpanda");

const http = @import("../http.zig");
const Network = @import("../Network.zig");
const hns_tlsa = @import("tlsa.zig");
const hns_spv = @import("spv.zig");
const hns_doh = @import("doh.zig");

/// Versioned wire schema. A field rename, removal, or type change here is a
/// schema change and must bump this string — see the pin tests at the
/// bottom of this file, which fail on exactly that.
pub const schema_version = "hns-verdict/1";

pub const ResolutionPath = enum {
    /// Resolved (and, when applicable, TLSA-checked) through the local
    /// hnsd SPV daemon: chain-anchored, not merely resolver-trusted.
    spv,
    /// Resolved (and, when applicable, TLSA-checked) through the
    /// configured DoH endpoint: TRUSTED, never "verified" (Lane T/D
    /// vocabulary law).
    doh,
    /// Plain OS resolution: either an ICANN name (never enters the HNS
    /// path at all) or a Handshake-shaped name with neither Handshake
    /// lane active (`--hns-resolver=off`, or no lane configured).
    os,
};

pub const DaneOutcome = enum {
    /// The served certificate matched a usable DANE-EE TLSA record. The
    /// connection this verdict describes (or a probe standing in for one)
    /// succeeded on that binding alone.
    matched,
    /// A usable DANE-EE TLSA record set exists but the served certificate
    /// matched none of it. The engine hard-fails such connections
    /// (X509_V_ERR_APPLICATION_VERIFICATION); this verdict reports that
    /// block, not a workaround for it.
    mismatch,
    /// The TLSA lookup completed cleanly (or, for `os`/off cases, DANE was
    /// never in scope) and found no usable DANE-EE record. Standard CA
    /// validation governs the connection, unchanged from upstream.
    absent,
    /// The TLSA lookup itself did not complete (transport failure, a
    /// non-NOERROR response, or, spv-only, an unvalidated answer). Nothing
    /// was confirmed either way.
    lookup_failed,
    /// DANE checking was never attempted: not a Handshake name, DANE
    /// disabled (`--hns-dane=off` or TLS verification off), or neither
    /// Handshake lane active.
    off,
};

pub const ResolverDetail = struct {
    /// doh path only: the DoH endpoint that answered.
    endpoint: ?[]const u8 = null,
    /// spv path only: hnsd's own locally-synced chain tip height at check
    /// time (vendor/hnsd `height.tip.chain.hnsd.` Hesiod status query).
    sync_height: ?u64 = null,
    /// spv path only: the chain tip's block time (unix seconds), when
    /// hnsd answered that query too. The header chain to `sync_height` is
    /// the actual SPV proof; this and `sync_height` are a receipt pointing
    /// at it, not a re-derivation of it.
    chain_time: ?i64 = null,
};

pub const MatchedRecord = struct {
    /// Always 3 (DANE-EE) — the only usage this fork's TLSA path accepts.
    usage: u8 = 3,
    /// 0 = full certificate, 1 = SubjectPublicKeyInfo.
    selector: u8,
    /// 0 = full (normalized to sha256 at parse time), 1 = sha256, 2 = sha512.
    matching_type: u8,
    /// Hex-encoded association data as published in the TLSA record.
    digest_hex: []const u8,
    /// Hex-encoded SPKI SHA-256, populated only when `selector == 1`: that
    /// is the only case where the record's own digest already *is* an SPKI
    /// digest. Never key material — this is a public-key hash, computed
    /// the same way DANE-EE(3)/SPKI(1)/SHA-256(1) is always computed.
    spki_sha256: ?[]const u8 = null,
};

pub const DaneResult = struct {
    outcome: []const u8,
    matched: ?MatchedRecord = null,
};

pub const RecordSeen = struct {
    rtype: []const u8 = "TLSA",
    usage: u8 = 3,
    selector: u8,
    matching_type: u8,
    digest_hex: []const u8,
};

pub const Evidence = struct {
    /// Every usable DANE-EE TLSA record the lookup returned (not just the
    /// one that matched, when there was a match).
    records_seen: []const RecordSeen = &.{},
    /// Free-form note: why a lookup_failed happened, that a mismatch
    /// blocked the connection, or a stated scope boundary on a passively
    /// observed (CDP) verdict. Never key material.
    detail: ?[]const u8 = null,
};

pub const Verdict = struct {
    schema: []const u8 = schema_version,
    name: []const u8,
    resolution_path: []const u8,
    resolver: ResolverDetail = .{},
    dane: DaneResult,
    /// True only when resolution_path is spv (vocabulary law) — and, even
    /// then, only when hnsd itself returned an AD-validated answer
    /// (matched, mismatch, or a validated-empty absent). A lookup_failed
    /// or off outcome is never verified: nothing was chain-validated.
    verified: bool,
    checked_at: lp.datetime.DateTime,
    evidence: Evidence = .{},
};

/// Pure: which lane a name's resolution goes through, given current
/// process-wide lane selection. No I/O. ICANN names and Handshake names
/// with neither lane active both report `.os` — the discriminator between
/// them is `hns_tlsa.isHnsName`, which callers apply separately when they
/// need it (e.g. to decide whether DANE is even in scope).
pub fn resolutionPathFor(host: []const u8) ResolutionPath {
    if (!hns_tlsa.isHnsName(host)) return .os;
    if (hns_spv.active()) return .spv;
    if (hns_doh.effectiveUrl() != null) return .doh;
    return .os;
}

/// Resolve `host` and check its DANE/TLSA binding WITHOUT fetching a page:
/// TLSA lookup over whichever lane is active, then (only when records
/// exist) a connect-only TLS probe — `http.Connection` with
/// `CURLOPT_CONNECT_ONLY=2`, the exact engine arm/verify path a real fetch
/// uses, stopped after the handshake and before any HTTP request goes out.
/// This is the "resolve + TLSA check only" primitive behind the MCP
/// `verdict` tool and the CDP `LP.getHnsVerdict` command.
pub fn compute(arena: std.mem.Allocator, network: *Network, host: []const u8, port: u16) !Verdict {
    const is_hns = hns_tlsa.isHnsName(host);
    const path = resolutionPathFor(host);
    const resolver = resolverDetailFor(path);
    const dane_globally_enabled = network.config.tlsVerifyHost() and network.config.hnsDaneEnabled();

    var empty_state: hns_tlsa.DaneState = .{};
    if (!is_hns or path == .os or !dane_globally_enabled) {
        return buildVerdict(arena, host, path, resolver, .off, &empty_state, null);
    }

    var state: hns_tlsa.DaneState = .{};
    const classify: hns_tlsa.LookupOutcome = if (path == .spv)
        hns_spv.lookupTlsaDetailed(&state, host, port)
    else
        hns_tlsa.lookupDetailed(&state, host, port, network.x509_store);

    switch (classify) {
        .failed => return buildVerdict(arena, host, path, resolver, .lookup_failed, &state, "TLSA lookup did not complete cleanly"),
        .empty => return buildVerdict(arena, host, path, resolver, .absent, &state, null),
        .armed => {
            var conn = http.Connection.init(network.x509_store, network.config, network.ip_filter) catch |err| {
                return buildVerdict(arena, host, path, resolver, .lookup_failed, &state, @errorName(err));
            };
            defer conn.deinit();
            conn.setConnectOnly(true) catch {};

            const url = std.fmt.allocPrintSentinel(arena, "https://{s}:{d}/", .{ host, port }, 0) catch |err| {
                return buildVerdict(arena, host, path, resolver, .lookup_failed, &state, @errorName(err));
            };

            const result: anyerror!u16 = blk: {
                conn.setURL(url) catch |e| break :blk e;
                break :blk conn.perform();
            };

            if (result) |_| {
                return buildVerdict(arena, host, path, resolver, .matched, &state, null);
            } else |err| {
                if (err == error.PeerFailedVerification) {
                    return buildVerdict(arena, host, path, resolver, .mismatch, &state, "connection blocked: served certificate matched no TLSA record");
                }
                return buildVerdict(arena, host, path, resolver, .lookup_failed, &state, @errorName(err));
            }
        },
    }
}

/// Build a verdict from a `hns_tlsa.DaneState` an already-completed
/// connection left behind (the CDP passive-observation path:
/// `Network.responseReceived` / `Network.loadingFailed`, network.zig). No
/// I/O beyond the same cheap resolver-detail lookup `compute` does.
///
/// A completed response can only mean `armed` -> matched (a mismatch hard-
/// fails the handshake before headers exist — see fail-closed inheritance
/// above) or `!armed` -> absent/off. Passive observation cannot distinguish
/// a clean empty TLSA answer from a failed lookup that also fell back to
/// standard CA validation (both leave the state unarmed); `compute`'s
/// active `resolve + TLSA check only` path can and does, which is exactly
/// why the MCP `verdict` tool exists alongside this.
pub fn fromObservedConnection(
    arena: std.mem.Allocator,
    name: []const u8,
    path: ResolutionPath,
    dane_enabled: bool,
    state: *const hns_tlsa.DaneState,
) !Verdict {
    const resolver = resolverDetailFor(path);
    const outcome: DaneOutcome = if (!dane_enabled or path == .os)
        .off
    else if (state.armed)
        .matched
    else
        .absent;
    const detail: ?[]const u8 = if (outcome == .absent)
        "observed post-hoc from a completed connection: a failed TLSA lookup and a validated-empty record set are not distinguished on this passive path — use the verdict tool/command for that distinction"
    else
        null;
    return buildVerdict(arena, name, path, resolver, outcome, state, detail);
}

/// Report the served DANE mismatch that just blocked a connection —
/// fail-closed inheritance: the surface reports what the engine did, never
/// overrides it. Called from `Network.loadingFailed`
/// (network.zig:httpRequestFail) when the failure was
/// `error.PeerFailedVerification` on an armed HNS connection.
pub fn fromBlockedConnection(
    arena: std.mem.Allocator,
    name: []const u8,
    path: ResolutionPath,
    state: *const hns_tlsa.DaneState,
) !Verdict {
    const resolver = resolverDetailFor(path);
    return buildVerdict(arena, name, path, resolver, .mismatch, state, "connection blocked: served certificate matched no TLSA record");
}

fn resolverDetailFor(path: ResolutionPath) ResolverDetail {
    return switch (path) {
        .spv => blk: {
            const cs = hns_spv.chainStatus() orelse break :blk .{};
            break :blk .{ .sync_height = cs.height, .chain_time = cs.chain_time };
        },
        .doh => .{ .endpoint = hns_doh.effectiveUrl() },
        .os => .{},
    };
}

/// Pure assembly: given an already-decided outcome and the DaneState that
/// produced it, build the final wire object. No I/O. Exercised directly by
/// the tests below (schema pin, one per outcome, spv-vs-doh distinction) so
/// those stay fast and deterministic — no live hnsd/DoH endpoint required.
fn buildVerdict(
    arena: std.mem.Allocator,
    name: []const u8,
    path: ResolutionPath,
    resolver: ResolverDetail,
    outcome: DaneOutcome,
    state: *const hns_tlsa.DaneState,
    detail: ?[]const u8,
) !Verdict {
    // Vocabulary law: verified only on the spv path, and only when hnsd
    // itself validated the answer (armed match/mismatch, or a validated-
    // empty absent). lookup_failed/off mean nothing was chain-validated.
    const verified = path == .spv and switch (outcome) {
        .matched, .mismatch, .absent => true,
        .lookup_failed, .off => false,
    };

    var matched: ?MatchedRecord = null;
    if (outcome == .matched and state.count > 0) {
        const rec = state.recs[0];
        const digest = try hexAlloc(arena, rec.hash[0..rec.len]);
        matched = .{
            .selector = rec.selector,
            .matching_type = rec.mtype,
            .digest_hex = digest,
            .spki_sha256 = if (rec.selector == 1) digest else null,
        };
    }

    return .{
        .name = name,
        .resolution_path = @tagName(path),
        .resolver = resolver,
        .dane = .{ .outcome = @tagName(outcome), .matched = matched },
        .verified = verified,
        .checked_at = lp.datetime.DateTime.now(),
        .evidence = .{ .records_seen = try recordsSeen(arena, state), .detail = detail },
    };
}

fn recordsSeen(arena: std.mem.Allocator, state: *const hns_tlsa.DaneState) ![]const RecordSeen {
    if (state.count == 0) return &.{};
    const list = try arena.alloc(RecordSeen, state.count);
    for (state.recs[0..state.count], 0..) |rec, i| {
        list[i] = .{
            .selector = rec.selector,
            .matching_type = rec.mtype,
            .digest_hex = try hexAlloc(arena, rec.hash[0..rec.len]),
        };
    }
    return list;
}

fn hexAlloc(arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const chars = "0123456789abcdef";
    const buf = try arena.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        buf[i * 2] = chars[b >> 4];
        buf[i * 2 + 1] = chars[b & 0xf];
    }
    return buf;
}

// -- tests -------------------------------------------------------------

const testing = @import("../../testing.zig");

fn fakeState(selector: u8, mtype: u8) hns_tlsa.DaneState {
    var state: hns_tlsa.DaneState = .{};
    state.count = 1;
    state.recs[0] = .{ .selector = selector, .mtype = mtype, .len = 32, .hash = undefined };
    @memset(state.recs[0].hash[0..32], 0xab);
    state.host_len = 0;
    return state;
}

// Schema pin: enumerates every field this phase shipped. A rename, removal,
// or type change on any of them makes this test fail with `error.MissingKey`
// (testing.expectJson does a subset match: every expected key must exist in
// the actual output with an equal value) — exactly "a schema change must
// break a test."
test "hns-verdict/1 - schema pin" {
    const aa = testing.arena_allocator;
    var state = fakeState(1, 1); // selector=SPKI, matching_type=sha256
    const v = try buildVerdict(aa, "web-a.endpoint.api.0xtestrun", .spv, .{ .sync_height = 342601, .chain_time = 1786672807 }, .matched, &state, null);
    const json = try std.json.Stringify.valueAlloc(aa, v, .{ .emit_null_optional_fields = false });

    try testing.expectJson(.{
        .schema = "hns-verdict/1",
        .name = "web-a.endpoint.api.0xtestrun",
        .resolution_path = "spv",
        .resolver = .{ .sync_height = 342601, .chain_time = 1786672807 },
        .dane = .{
            .outcome = "matched",
            .matched = .{
                .usage = 3,
                .selector = 1,
                .matching_type = 1,
                .digest_hex = "abababababababababababababababababababababababababababababababab",
                .spki_sha256 = "abababababababababababababababababababababababababababababababab",
            },
        },
        .verified = true,
        .evidence = .{
            .records_seen = &.{.{
                .rtype = "TLSA",
                .usage = 3,
                .selector = 1,
                .matching_type = 1,
                .digest_hex = "abababababababababababababababababababababababababababababababab",
            }},
        },
    }, json);

    // checked_at exists and parses as a timestamp — schema pin doesn't
    // pin its literal value (it's wall-clock), but its presence and shape.
    try testing.expect(std.mem.indexOf(u8, json, "\"checked_at\":\"") != null);
}

test "hns-verdict/1 - dane outcome: matched" {
    const aa = testing.arena_allocator;
    var state = fakeState(1, 1);
    const v = try buildVerdict(aa, "web-a.endpoint.api.0xtestrun", .spv, .{}, .matched, &state, null);
    try testing.expectEqualSlices(u8, "matched", v.dane.outcome);
    try testing.expect(v.dane.matched != null);
    try testing.expectEqual(true, v.verified);
}

test "hns-verdict/1 - dane outcome: mismatch" {
    const aa = testing.arena_allocator;
    var state = fakeState(1, 1);
    const v = try buildVerdict(aa, "dane-b.endpoint.api.0xtestrun", .spv, .{}, .mismatch, &state, "connection blocked: served certificate matched no TLSA record");
    try testing.expectEqualSlices(u8, "mismatch", v.dane.outcome);
    // The mismatch is against a real record set; report what was seen, but
    // never claim a specific record "matched" when nothing did.
    try testing.expect(v.dane.matched == null);
    try testing.expectEqual(@as(usize, 1), v.evidence.records_seen.len);
    try testing.expectEqual(true, v.verified);
    try testing.expect(v.evidence.detail != null);
}

test "hns-verdict/1 - dane outcome: absent" {
    const aa = testing.arena_allocator;
    var empty_state: hns_tlsa.DaneState = .{};
    const v = try buildVerdict(aa, "no-tlsa.endpoint.api.0xtestrun", .doh, .{ .endpoint = "https://hnsdoh.com/dns-query" }, .absent, &empty_state, null);
    try testing.expectEqualSlices(u8, "absent", v.dane.outcome);
    try testing.expectEqual(@as(usize, 0), v.evidence.records_seen.len);
    // doh path: never verified, per the vocabulary law.
    try testing.expectEqual(false, v.verified);
}

test "hns-verdict/1 - dane outcome: lookup_failed" {
    const aa = testing.arena_allocator;
    var empty_state: hns_tlsa.DaneState = .{};
    const v = try buildVerdict(aa, "unreachable.endpoint.api.0xtestrun", .spv, .{}, .lookup_failed, &empty_state, "TLSA lookup did not complete cleanly");
    try testing.expectEqualSlices(u8, "lookup_failed", v.dane.outcome);
    // A failed lookup validated nothing, even on the spv path.
    try testing.expectEqual(false, v.verified);
    try testing.expect(v.evidence.detail != null);
}

test "hns-verdict/1 - dane outcome: off" {
    const aa = testing.arena_allocator;
    var empty_state: hns_tlsa.DaneState = .{};
    const v = try buildVerdict(aa, "example.com", .os, .{}, .off, &empty_state, null);
    try testing.expectEqualSlices(u8, "off", v.dane.outcome);
    try testing.expectEqualSlices(u8, "os", v.resolution_path);
    try testing.expectEqual(false, v.verified);
}

test "hns-verdict/1 - resolutionPathFor: ICANN name is always os" {
    try testing.expectEqual(ResolutionPath.os, resolutionPathFor("example.com"));
}

test "hns-verdict/1 - spv vs doh path distinction: identical dane state, different verified" {
    const aa = testing.arena_allocator;
    var state = fakeState(1, 1);

    const spv_verdict = try buildVerdict(aa, "web-a.endpoint.api.0xtestrun", .spv, .{ .sync_height = 342601 }, .matched, &state, null);
    const doh_verdict = try buildVerdict(aa, "web-a.endpoint.api.0xtestrun", .doh, .{ .endpoint = "https://hnsdoh.com/dns-query" }, .matched, &state, null);

    try testing.expectEqualSlices(u8, "spv", spv_verdict.resolution_path);
    try testing.expectEqualSlices(u8, "doh", doh_verdict.resolution_path);
    try testing.expectEqual(true, spv_verdict.verified);
    try testing.expectEqual(false, doh_verdict.verified);

    // Both report the same underlying record evidence — the distinction is
    // strictly resolution_path/verified, never a different dane shape.
    try testing.expectEqual(spv_verdict.evidence.records_seen.len, doh_verdict.evidence.records_seen.len);
    try testing.expectEqualSlices(u8, spv_verdict.dane.outcome, doh_verdict.dane.outcome);
}

test "hns-verdict/1 - matched record SPKI digest only populated for selector=SPKI" {
    const aa = testing.arena_allocator;
    var full_cert_state = fakeState(0, 1); // selector=full certificate, not SPKI
    const v = try buildVerdict(aa, "web-a.endpoint.api.0xtestrun", .spv, .{}, .matched, &full_cert_state, null);
    try testing.expect(v.dane.matched != null);
    try testing.expect(v.dane.matched.?.digest_hex.len > 0);
    // Never any key material, and never a false SPKI claim: selector=0 is a
    // full-certificate digest, not a public-key digest.
    try testing.expect(v.dane.matched.?.spki_sha256 == null);
}
