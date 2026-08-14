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

// Lane S — VERIFIED Handshake resolution via a local hnsd SPV daemon.
//
// hnsd (github.com/handshake-org/hnsd, MIT) is a light client that syncs
// Handshake block headers peer-to-peer, derives the name-root committed on
// chain, and serves a recursive validating resolver on localhost. Answers
// it validates carry the AD flag; the trust anchor is the chain itself, not
// any remote resolver. When this lane is active:
//   - Handshake names resolve through hnsd (verified; AD required),
//   - TLSA records for DANE come from hnsd too, so the Lane D check
//     upgrades from TRUSTED to verified without changing shape,
//   - the DoH lane (trusted) is not selected; it remains the automatic
//     fallback for sessions where no hnsd is available,
//   - ICANN names use plain OS resolution, byte-identical to upstream.
//
// Fail-closed: an hnsd lookup that fails or comes back unvalidated is a
// resolution failure for that name. It is never silently downgraded to the
// trusted DoH channel mid-session; lane selection happens once, at startup,
// and is logged.

const std = @import("std");
const builtin = @import("builtin");
const lp = @import("lightpanda");

const Config = @import("../../Config.zig");
const sys_net = @import("../../sys/net.zig");
const tlsa = @import("tlsa.zig");

const log = lp.log;

/// Default address the sidecar binds and `auto` mode probes.
pub const default_addr = "127.0.0.1";
pub const default_port: u16 = 15353;

/// Port hnsd's root-nameserver Hesiod status channel binds to when this
/// process spawns the sidecar (`-n`, distinct from the recursive resolver
/// `-r` port above — hnsd runs both listeners). Chosen off the beaten path
/// like `default_port`, rather than hnsd's own network default (5349 on
/// mainnet, `vendor/hnsd/docs/hesiod.md`), to avoid colliding with an
/// unrelated hnsd instance a user might already have running on the
/// well-known port. Only meaningful for a sidecar THIS process spawned
/// (`hesiod_addr` below) — an attached, externally-run daemon's Hesiod
/// port is unknown to us and not guessed at.
const hesiod_port: u16 = 15349;

/// Where `auto` mode looks for an hnsd binary when nothing is running.
/// A configured --hnsd-path always wins. `vendor/hnsd/hnsd` is checked
/// first (repo-relative — the output of `zig build hnsd`, for `zig build
/// run` invoked from the repo root); "hnsd" resolves via PATH after that.
const binary_candidates = [_][]const u8{
    "vendor/hnsd/hnsd",
    "hnsd",
    "/opt/homebrew/bin/hnsd",
    "/usr/local/bin/hnsd",
};

const query_timeout_ms: i32 = 3000;
const spawn_ready_ms: u64 = 10_000;

var active_state = false;
var selected = false;
var addr: sys_net.IpAddress = undefined;
/// Set only when this process spawned the sidecar and pinned its Hesiod
/// port with `-n` (see `spawn`); null for an attached daemon, or before
/// spawn completes. `chainStatus`/`queryHesiod` degrade to their existing
/// "unavailable" null result when this is unset — no regression, just no
/// resolver detail, same as before this port was known at all.
var hesiod_addr: ?sys_net.IpAddress = null;
var child: ?std.process.Child = null;
// Io used to spawn and later reap the sidecar. lp.io cannot spawn children
// (failing allocator, empty environ); this one lives as long as the child.
var child_threaded: ?std.Io.Threaded = null;

pub fn active() bool {
    return active_state;
}

/// One-shot lane selection, called from Network.init before the connection
/// pool is built (single-threaded; read-only afterwards).
///
/// Precedence: --hns-resolver=off or =doh disables this lane outright (the
/// master selector, item 3). Otherwise an explicit --hns-doh-url (URL or
/// `off`) is a user choice of the DoH lane or of no HNS resolution, and
/// disables SPV. Otherwise --hns-spv: `off` disables; `host:port` attaches
/// to a running daemon; `auto` (default) attaches to a daemon on the
/// default port, or spawns the sidecar when an hnsd binary can be found, or
/// leaves the lane inactive so the trusted DoH lane is selected instead.
pub fn select(allocator: std.mem.Allocator, config: *const Config) void {
    if (selected) return;
    selected = true;
    active_state = false;

    // The probe/spawn below touch the network and the filesystem.
    if (builtin.is_test) return;

    switch (config.hnsResolver()) {
        .off => {
            log.info(.http, "hns spv skipped", .{ .reason = "--hns-resolver=off" });
            return;
        },
        .doh => {
            log.info(.http, "hns spv skipped", .{ .reason = "--hns-resolver=doh" });
            return;
        },
        .spv => {},
    }

    if (config.hnsDohUrl() != null) {
        log.info(.http, "hns spv skipped", .{ .reason = "explicit --hns-doh-url" });
        return;
    }

    const mode = config.hnsSpv() orelse "auto";
    if (std.mem.eql(u8, mode, "off")) {
        log.info(.http, "hns spv disabled", .{ .arg = "--hns-spv", .value = "off" });
        return;
    }

    if (!std.mem.eql(u8, mode, "auto")) {
        // Explicit host:port — attach only, never spawn.
        addr = sys_net.IpAddress.parseLiteral(mode) catch {
            log.warn(.http, "hns spv bad address", .{ .value = mode });
            return;
        };
        if (probe()) {
            activate("attached");
        } else {
            log.warn(.http, "hns spv startup failed, downgrading to TRUSTED doh for this session", .{ .reason = "unreachable", .value = mode });
        }
        return;
    }

    // auto: attach to an already-running daemon first.
    addr = sys_net.IpAddress.parse(default_addr, default_port) catch unreachable;
    if (probe()) {
        activate("attached");
        return;
    }

    // Then try to spawn the sidecar.
    if (spawn(allocator, config)) {
        activate("spawned");
        return;
    }
    log.warn(.http, "hns spv startup failed, downgrading to TRUSTED doh for this session", .{ .reason = "no daemon reachable, sidecar spawn failed" });
}

fn activate(how: []const u8) void {
    active_state = true;
    log.info(.http, "hns spv enabled", .{
        .mode = how,
        .port = default_port,
        .trust = "verified, local spv chain",
    });
}

/// Kill the sidecar if this process spawned one. Attached daemons are left
/// alone.
pub fn shutdown() void {
    if (child) |*ch| {
        const io = child_threaded.?.io();
        // SIGKILL, not SIGTERM: the browser blocks signals on the main
        // thread (a dedicated sigwait thread handles them) and the forked
        // sidecar inherits that mask, so blockable signals never reach it.
        // hnsd's checkpoint is crash-safe.
        if (ch.id) |pid| _ = std.c.kill(pid, std.posix.SIG.KILL);
        ch.kill(io);
        child = null;
        hesiod_addr = null;
        child_threaded.?.deinit();
        child_threaded = null;
    }
}

fn spawn(allocator: std.mem.Allocator, config: *const Config) bool {
    const path = findBinary(config) orelse return false;

    var port_buf: [32]u8 = undefined;
    const listen = std.fmt.bufPrint(&port_buf, "{s}:{d}", .{ default_addr, default_port }) catch return false;

    // Pin the Hesiod status channel too (hnsd runs it as a second listener,
    // independent of -r) so queryHesiod knows where to reach it. See
    // hesiod_port's doc comment for why this isn't hnsd's own 5349 default.
    var hesiod_listen_buf: [32]u8 = undefined;
    const hesiod_listen = std.fmt.bufPrint(&hesiod_listen_buf, "{s}:{d}", .{ default_addr, hesiod_port }) catch return false;

    // Persistent header/checkpoint dir so later sessions start warm.
    var dir_buf: [512]u8 = undefined;
    const datadir: ?[]const u8 = if (std.c.getenv("HOME")) |h|
        std.fmt.bufPrint(&dir_buf, "{s}/.lightpanda/hnsd", .{std.mem.span(h)}) catch null
    else
        null;
    if (datadir) |d| std.Io.Dir.cwd().createDirPath(lp.io, d) catch {};

    var argv_buf: [8][]const u8 = undefined;
    var argc: usize = 0;
    argv_buf[argc] = path;
    argc += 1;
    argv_buf[argc] = "-r";
    argc += 1;
    argv_buf[argc] = listen;
    argc += 1;
    argv_buf[argc] = "-n";
    argc += 1;
    argv_buf[argc] = hesiod_listen;
    argc += 1;
    if (datadir) |d| {
        argv_buf[argc] = "-x";
        argc += 1;
        argv_buf[argc] = d;
        argc += 1;
    }

    // lp.io cannot spawn children (failing allocator, empty environ); use a
    // dedicated Threaded Io carrying the real environment, kept alive until
    // shutdown reaps the child.
    var env_map = lp.environMap(allocator) catch |err| {
        log.warn(.http, "hns spv spawn failed", .{ .path = path, .err = err });
        return false;
    };
    defer env_map.deinit();

    child_threaded = .init(allocator, .{ .environ = lp.environ() });
    const child_io = child_threaded.?.io();

    var ch = std.process.spawn(child_io, .{
        .argv = argv_buf[0..argc],
        .environ_map = &env_map,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch |err| {
        log.warn(.http, "hns spv spawn failed", .{ .path = path, .err = err });
        child_threaded.?.deinit();
        child_threaded = null;
        return false;
    };

    // Wait for the DNS port to answer.
    const deadline = lp.datetime.timestamp(.boot) + spawn_ready_ms;
    while (lp.datetime.timestamp(.boot) < deadline) {
        if (probe()) {
            child = ch;
            hesiod_addr = sys_net.IpAddress.parse(default_addr, hesiod_port) catch null;
            log.info(.http, "hns spv sidecar ready", .{ .path = path });
            return true;
        }
        lp.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }

    log.warn(.http, "hns spv sidecar not ready", .{ .path = path });
    if (ch.id) |pid| _ = std.c.kill(pid, std.posix.SIG.KILL);
    ch.kill(child_io);
    child_threaded.?.deinit();
    child_threaded = null;
    return false;
}

var found_path_buf: [1024]u8 = undefined;

fn findBinary(config: *const Config) ?[]const u8 {
    if (config.hnsdPath()) |p| return p;
    for (binary_candidates) |cand| {
        if (std.mem.indexOfScalar(u8, cand, '/') == null) {
            // Bare name: resolve via PATH ourselves; the spawn Io carries
            // no environ, so argv[0] must be a full path.
            if (pathLookup(cand)) |full| return full;
            continue;
        }
        std.Io.Dir.cwd().access(lp.io, cand, .{}) catch continue;
        return cand;
    }
    return null;
}

fn pathLookup(name: []const u8) ?[]const u8 {
    const path_env = std.c.getenv("PATH") orelse return null;
    var it = std.mem.splitScalar(u8, std.mem.span(path_env), ':');
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const full = std.fmt.bufPrint(&found_path_buf, "{s}/{s}", .{ dir, name }) catch continue;
        std.Io.Dir.cwd().access(lp.io, full, .{}) catch continue;
        return full;
    }
    return null;
}

/// Readiness probe: SOA for the root answers over TCP.
fn probe() bool {
    var qbuf: [64]u8 = undefined;
    var rbuf: [512]u8 = undefined;
    const resp = query(&qbuf, ".", 6, &rbuf) orelse return false;
    return resp.len >= 12;
}

pub const Resolved = struct {
    /// Comma-separated IP list in CURLOPT_RESOLVE format, e.g. "1.2.3.4,::1".
    ips: [512]u8 = undefined,
    len: usize = 0,
    validated: bool = false,

    pub fn list(self: *const Resolved) []const u8 {
        return self.ips[0..self.len];
    }
};

/// Resolve A and AAAA for `host` through hnsd. Returns false when nothing
/// resolves or the answer is not validated (AD unset) — fail-closed; the
/// caller treats that as a failed resolution, never as a downgrade.
pub fn resolve(host: []const u8, out: *Resolved) bool {
    // A sidecar this process just spawned may still be catching its chain
    // up from the checkpoint; give the first resolutions a grace window
    // instead of failing page one of the session. Attached daemons are
    // assumed synced (no retry).
    const attempts: usize = if (child != null and !resolved_once) 30 else 1;
    var attempt: usize = 0;
    while (attempt < attempts) : (attempt += 1) {
        if (attempt > 0) lp.io.sleep(.fromMilliseconds(500), .awake) catch {};
        if (resolveOnce(host, out)) {
            resolved_once = true;
            return true;
        }
    }
    log.warn(.http, "hns spv resolve failed", .{ .host = host });
    return false;
}

var resolved_once = false;

fn resolveOnce(host: []const u8, out: *Resolved) bool {
    out.len = 0;
    out.validated = false;

    var any_ad = false;
    inline for (.{ tlsa.TYPE_A, tlsa.TYPE_AAAA }) |qtype| {
        var qbuf: [320]u8 = undefined;
        var rbuf: [2048]u8 = undefined;
        if (query(&qbuf, host, qtype, &rbuf)) |msg| {
            const flags = std.mem.readInt(u16, msg[2..4], .big);
            if (flags & 0xf == 0) { // NOERROR
                if (flags & 0x20 != 0) any_ad = true; // AD
                collectAddrs(msg, qtype, out);
            }
        }
    }

    if (out.len == 0) return false;
    if (!any_ad) {
        log.warn(.http, "hns spv answer unvalidated", .{ .host = host });
        out.len = 0;
        return false;
    }
    out.validated = true;
    return true;
}

/// TLSA via hnsd: same DaneState contract as tlsa.lookup, but the records
/// arrive over the local SPV-validated channel. Requires AD; an unvalidated
/// TLSA answer is treated as absent (fail-closed to CA validation).
pub fn lookupTlsa(state: *tlsa.DaneState, host: []const u8, port: u16) u8 {
    return switch (lookupTlsaDetailed(state, host, port)) {
        .failed, .empty => 0,
        .armed => |n| n,
    };
}

/// Same lookup as `lookupTlsa`, reporting `tlsa.LookupOutcome` instead of
/// collapsing failure and confirmed-absence into the same 0. See
/// tlsa.LookupOutcome doc comment: the engine's own fail-closed behavior is
/// unchanged either way; only the reporting is richer (the agent verdict
/// surface, verdict.zig, is the consumer).
///
/// Carries the same "just-spawned sidecar" grace window `resolve` already
/// has (see its doc comment): a sidecar this process spawned may still be
/// catching its chain up from the checkpoint when the very first HNS
/// operation of the session is a standalone TLSA/verdict check rather than
/// a page fetch (which goes through `resolve` first). Without this, that
/// first check spuriously reports `.failed` for a daemon that would have
/// answered correctly a second later — observed directly: a verdict check
/// fired immediately after "hns spv sidecar ready" failed in under a
/// millisecond, while the identical check 20s later succeeded. Retries only
/// on `.failed` (transport failure or an unvalidated answer) — a validated
/// `.empty` is a real, chain-confirmed absence and is never retried.
/// Attached (not spawned) daemons are assumed synced, same as `resolve`.
pub fn lookupTlsaDetailed(state: *tlsa.DaneState, host: []const u8, port: u16) tlsa.LookupOutcome {
    const attempts: usize = if (child != null and !resolved_once) 30 else 1;
    var attempt: usize = 0;
    while (attempt < attempts) : (attempt += 1) {
        if (attempt > 0) lp.io.sleep(.fromMilliseconds(500), .awake) catch {};
        const outcome = lookupTlsaOnce(state, host, port);
        if (outcome != .failed) {
            resolved_once = true;
            return outcome;
        }
    }
    return .failed;
}

fn lookupTlsaOnce(state: *tlsa.DaneState, host: []const u8, port: u16) tlsa.LookupOutcome {
    tlsa.clear(state);
    if (host.len > 253) return .failed;

    var qname_buf: [280]u8 = undefined;
    const qname = std.fmt.bufPrint(&qname_buf, "_{d}._tcp.{s}", .{ port, host }) catch return .failed;

    var qbuf: [384]u8 = undefined;
    var rbuf: [8192]u8 = undefined;
    const msg = query(&qbuf, qname, tlsa.TYPE_TLSA, &rbuf) orelse {
        log.warn(.http, "hns spv tlsa failed", .{ .host = host });
        return .failed;
    };

    const flags = std.mem.readInt(u16, msg[2..4], .big);
    if (flags & 0xf != 0) return .failed;
    if (flags & 0x20 == 0) {
        log.warn(.http, "hns spv tlsa unvalidated", .{ .host = host });
        return .failed;
    }

    const n = tlsa.parseTlsa(msg, state);
    if (n > 0) {
        state.host_len = @intCast(host.len);
        @memcpy(state.host[0..host.len], host);
        state.verified = true;
        state.armed = true;
        log.info(.http, "hns dane armed", .{ .host = host, .records = n, .trust = "verified spv channel" });
        return .{ .armed = n };
    }
    return .empty;
}

/// hnsd's own SPV status, read over its local Hesiod-class status channel
/// (vendor/hnsd/src/hesiod.c: `height.tip.chain.hnsd.` / `time.tip.chain.hnsd.`,
/// class HS TXT). Used by the agent verdict surface as the spv-path
/// "resolver detail" and evidence.proof reference — the locally-synced
/// header chain to this height IS the SPV proof; this is a receipt
/// pointing at it, not a re-derivation. Returns null when the lane isn't
/// active or either query fails; a missing chain_time (the rarer of the
/// two) doesn't invalidate the height.
pub const ChainStatus = struct {
    height: u64,
    chain_time: ?i64 = null,
};

pub fn chainStatus() ?ChainStatus {
    if (!active_state) return null;

    var hqbuf: [80]u8 = undefined;
    var hrbuf: [512]u8 = undefined;
    const hmsg = queryHesiod(&hqbuf, "height.tip.chain.hnsd.", &hrbuf) orelse return null;
    const htxt = extractFirstTxt(hmsg) orelse return null;
    const height = std.fmt.parseInt(u64, htxt, 10) catch return null;

    var tqbuf: [80]u8 = undefined;
    var trbuf: [512]u8 = undefined;
    const chain_time: ?i64 = blk: {
        const tmsg = queryHesiod(&tqbuf, "time.tip.chain.hnsd.", &trbuf) orelse break :blk null;
        const ttxt = extractFirstTxt(tmsg) orelse break :blk null;
        break :blk std.fmt.parseInt(i64, ttxt, 10) catch null;
    };

    return .{ .height = height, .chain_time = chain_time };
}

fn queryHesiod(qbuf: []u8, qname: []const u8, rbuf: []u8) ?[]const u8 {
    const target = hesiod_addr orelse return null;
    const q = tlsa.buildQueryClass(qbuf, qname, tlsa.TYPE_TXT, tlsa.CLASS_HESIOD) orelse return null;
    return sendRecv(target, q, rbuf);
}

/// First TXT record's character-string content, or null on anything that
/// doesn't parse as a single clean answer (not NOERROR, no answers, wrong
/// type, malformed rdata).
fn extractFirstTxt(msg: []const u8) ?[]const u8 {
    if (msg.len < 12) return null;
    const flags = std.mem.readInt(u16, msg[2..4], .big);
    if (flags & 0xf != 0) return null;
    const qd = std.mem.readInt(u16, msg[4..6], .big);
    const an = std.mem.readInt(u16, msg[6..8], .big);
    if (an == 0) return null;

    var o: usize = 12;
    var i: usize = 0;
    while (i < qd) : (i += 1) {
        o = (tlsa.skipName(msg, o) orelse return null) + 4;
        if (o > msg.len) return null;
    }

    o = tlsa.skipName(msg, o) orelse return null;
    if (o + 10 > msg.len) return null;
    const rtype = std.mem.readInt(u16, msg[o..][0..2], .big);
    const rdlen = std.mem.readInt(u16, msg[o + 8 ..][0..2], .big);
    o += 10;
    if (rdlen == 0 or o + rdlen > msg.len) return null;
    if (rtype != tlsa.TYPE_TXT) return null;

    const rdata = msg[o .. o + rdlen];
    const txt_len = rdata[0];
    if (1 + @as(usize, txt_len) > rdata.len) return null;
    return rdata[1..][0..txt_len];
}

fn collectAddrs(msg: []const u8, want: u16, out: *Resolved) void {
    const qd = std.mem.readInt(u16, msg[4..6], .big);
    const an = std.mem.readInt(u16, msg[6..8], .big);
    var o: usize = 12;
    var i: usize = 0;
    while (i < qd) : (i += 1) {
        o = (tlsa.skipName(msg, o) orelse return) + 4;
        if (o > msg.len) return;
    }
    i = 0;
    while (i < an) : (i += 1) {
        o = tlsa.skipName(msg, o) orelse return;
        if (o + 10 > msg.len) return;
        const rtype = std.mem.readInt(u16, msg[o..][0..2], .big);
        const rdlen = std.mem.readInt(u16, msg[o + 8 ..][0..2], .big);
        o += 10;
        if (o + rdlen > msg.len) return;
        const rdata = msg[o .. o + rdlen];
        o += rdlen;

        var text_buf: [64]u8 = undefined;
        var text: []const u8 = "";
        if (rtype == want and want == tlsa.TYPE_A and rdlen == 4) {
            text = std.fmt.bufPrint(&text_buf, "{d}.{d}.{d}.{d}", .{ rdata[0], rdata[1], rdata[2], rdata[3] }) catch continue;
        } else if (rtype == want and want == tlsa.TYPE_AAAA and rdlen == 16) {
            const a6 = sys_net.IpAddress.parseIp6("::", 0) catch continue;
            _ = a6;
            // Format the 16 bytes as full hex groups; curl accepts it.
            text = std.fmt.bufPrint(&text_buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                rdata[0],  rdata[1],  rdata[2],  rdata[3],
                rdata[4],  rdata[5],  rdata[6],  rdata[7],
                rdata[8],  rdata[9],  rdata[10], rdata[11],
                rdata[12], rdata[13], rdata[14], rdata[15],
            }) catch continue;
        } else continue;

        if (out.len + text.len + 1 > out.ips.len) return;
        if (out.len > 0) {
            out.ips[out.len] = ',';
            out.len += 1;
        }
        @memcpy(out.ips[out.len..][0..text.len], text);
        out.len += text.len;
    }
}

// One DNS query over UDP against the hnsd address (its recursive listener
// is UDP-only). The AD bit is set on the query so hnsd reports validation
// in the response; no DO bit is set, so answers stay compact (no RRSIGs on
// the wire). A truncated (TC) response is treated as a failed lookup.
fn query(qbuf: []u8, qname: []const u8, qtype: u16, rbuf: []u8) ?[]const u8 {
    const q = tlsa.buildQuery(qbuf, qname, qtype) orelse return null;
    // AD bit in the query: byte 3, bit 0x20.
    qbuf[3] |= 0x20;
    return sendRecv(addr, q, rbuf);
}

// Shared UDP send/receive against an hnsd listener, used by both the
// Handshake-name `query` above (IN class, AD requested, the recursive
// resolver at `addr`) and the Hesiod status `queryHesiod` (HS class,
// chainStatus below, hnsd's SEPARATE root-nameserver listener at
// `hesiod_addr` — confirmed distinct from the recursive resolver: hnsd
// REFUSEs an HS-class query on the resolver port) — same socket, timeout,
// and truncation handling either way, just a different target address.
fn sendRecv(target: sys_net.IpAddress, q: []const u8, rbuf: []u8) ?[]const u8 {
    const sock = sys_net.socket(sys_net.family(&target), std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP) catch return null;
    defer _ = std.c.close(sock);
    setTimeouts(sock);

    const sa = sys_net.sockaddrFromAddress(&target);
    if (std.c.connect(sock, sa.ptr(), sa.len) != 0) return null;
    if (std.c.send(sock, q.ptr, q.len, 0) != q.len) return null;

    const n = std.c.recv(sock, rbuf.ptr, rbuf.len, 0);
    if (n < 12) return null;
    const msg = rbuf[0..@intCast(n)];
    const flags = std.mem.readInt(u16, msg[2..4], .big);
    if (flags & 0x0200 != 0) return null; // TC: truncated, fail closed
    return msg;
}

fn setTimeouts(sock: sys_net.socket_t) void {
    const tv = std.posix.timeval{
        .sec = @intCast(@divTrunc(query_timeout_ms, 1000)),
        .usec = @intCast(@mod(query_timeout_ms, 1000) * 1000),
    };
    std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
}
