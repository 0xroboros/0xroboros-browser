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

// DANE/TLSA for Handshake names (Lane D).
//
// TRUSTED end-to-end: TLSA records arrive over the same configured DoH
// channel as A records, so this check is only as strong as the resolver
// answering. Lane S (hnsd SPV) upgrades this same path to verified records.
//
// Scope, fail-closed throughout (RFC 6698 / 7671 subset):
// - certificate usage DANE-EE(3) only; other usages are unusable here and
//   an all-unusable TLSA set falls back to standard CA validation.
// - selectors Cert(0) and SPKI(1); matching types Full(0), SHA-256(1),
//   SHA-512(2). Full(0) association data is normalized to its SHA-256 at
//   parse time and compared against the SHA-256 of the presented DER,
//   which is equivalent to byte comparison.
// - ICANN names never enter this path (see icann_tlds.zig); their TLS
//   handling is byte-identical to upstream. There is no accept-any
//   fallback under any failure, anywhere.

const std = @import("std");
const lp = @import("lightpanda");

const libcurl = @import("../../sys/libcurl.zig");
const crypto = @import("../../sys/libcrypto.zig");
const doh = @import("doh.zig");
const icann = @import("icann_tlds.zig");

const log = lp.log;

pub const X509_STORE_CTX = opaque {};
const X509_PUBKEY = opaque {};
const SSL = opaque {};

// X509_V_ERR_APPLICATION_VERIFICATION: reported on TLSA mismatch so curl's
// post-handshake SSL_get_verify_result check fails closed even though the
// handshake itself runs under SSL_VERIFY_NONE.
const X509_V_ERR_APPLICATION_VERIFICATION: c_int = 50;
const TLSEXT_NAMETYPE_host_name: c_int = 0;

extern fn X509_STORE_CTX_get0_cert(ctx: *const X509_STORE_CTX) ?*crypto.X509;
extern fn X509_STORE_CTX_set_error(ctx: *X509_STORE_CTX, err: c_int) void;
extern fn X509_STORE_CTX_get_ex_data(ctx: *const X509_STORE_CTX, idx: c_int) ?*anyopaque;
extern fn SSL_get_ex_data_X509_STORE_CTX_idx() c_int;
extern fn SSL_get_servername(ssl: *const SSL, ty: c_int) ?[*:0]const u8;
extern fn X509_verify_cert(ctx: *X509_STORE_CTX) c_int;
extern fn X509_digest(x: *const crypto.X509, md: *const crypto.EVP_MD, out: [*]u8, out_len: *c_uint) c_int;
extern fn X509_get_X509_PUBKEY(x: *const crypto.X509) ?*X509_PUBKEY;
extern fn i2d_X509_PUBKEY(key: *const X509_PUBKEY, outp: ?*[*]u8) c_int;
pub extern fn SSL_CTX_set_cert_verify_callback(
    ctx: *crypto.SSL_CTX,
    cb: *const fn (*X509_STORE_CTX, ?*anyopaque) callconv(.c) c_int,
    arg: ?*anyopaque,
) void;

const lookup_timeout_ms: c_long = 3000;
const max_records = 16;

const Rec = struct {
    selector: u8, // 0 = full certificate, 1 = SubjectPublicKeyInfo
    mtype: u8, // 0 = full (stored as sha-256), 1 = sha-256, 2 = sha-512
    len: u8, // 32 or 64
    hash: [64]u8,
};

/// Per-connection DANE state, embedded in http.Connection. No allocation.
pub const DaneState = struct {
    armed: bool = false,
    /// True when the records arrived over the local SPV-validated channel
    /// (Lane S); false means the trusted DoH channel (Lane T/D wording).
    verified: bool = false,
    count: u8 = 0,
    host: [254]u8 = undefined,
    host_len: u8 = 0,
    recs: [max_records]Rec = undefined,

    pub fn hostname(self: *const DaneState) []const u8 {
        return self.host[0..self.host_len];
    }
};

/// True when `host` should go through the HNS DANE path: not an IP
/// literal, not single-label localhost-style, and its TLD is not in the
/// ICANN root. ICANN names keep upstream CA validation untouched.
pub fn isHnsName(host: []const u8) bool {
    if (host.len == 0 or host.len > 253) return false;
    if (std.mem.indexOfScalar(u8, host, ':') != null) return false; // IPv6
    const trimmed = std.mem.trimEnd(u8, host, ".");
    const tld = trimmed[(std.mem.lastIndexOfScalar(u8, trimmed, '.') orelse 0)..];
    const label = std.mem.trimStart(u8, tld, ".");
    if (label.len == 0) return false;
    // All-numeric final label: IPv4 literal.
    for (label) |ch| {
        if (!std.ascii.isDigit(ch)) break;
    } else return false;
    return !icann.isIcannTld(label);
}

/// Fetch TLSA for `_<port>._tcp.<host>` through the effective Lane T DoH
/// endpoint and fill `state`. Returns the number of usable DANE-EE records.
/// Any failure (no endpoint, network, HTTP, SERVFAIL, parse) returns 0:
/// the caller treats that exactly like an absent TLSA set (standard CA
/// validation), never as a pass.
pub fn lookup(state: *DaneState, host: []const u8, port: u16, x509_store: *crypto.X509_STORE) u8 {
    state.armed = false;
    state.count = 0;

    const doh_url = doh.effectiveUrl() orelse return 0;
    if (host.len > 253) return 0;

    var qname_buf: [280]u8 = undefined;
    const qname = std.fmt.bufPrint(&qname_buf, "_{d}._tcp.{s}", .{ port, host }) catch return 0;

    var query_buf: [384]u8 = undefined;
    const query = buildQuery(&query_buf, qname, TYPE_TLSA) orelse return 0;

    var b64_buf: [512]u8 = undefined;
    const b64 = std.base64.url_safe_no_pad.Encoder.encode(&b64_buf, query);

    var url_buf: [1024:0]u8 = undefined;
    const url = std.fmt.bufPrintZ(&url_buf, "{s}?dns={s}", .{ doh_url, b64 }) catch return 0;

    var resp: Response = .{};
    if (!fetch(url, x509_store, &resp)) {
        log.warn(.http, "hns dane lookup failed", .{ .host = host });
        return 0;
    }

    const n = parseTlsa(resp.buf[0..resp.len], state);
    if (n > 0) {
        state.host_len = @intCast(host.len);
        @memcpy(state.host[0..host.len], host);
        state.armed = true;
        log.info(.http, "hns dane armed", .{ .host = host, .records = n, .trust = "trusted doh channel" });
    }
    return n;
}

/// Disarm; the connection reverts to plain Lane T behavior.
pub fn clear(state: *DaneState) void {
    state.armed = false;
    state.verified = false;
    state.count = 0;
    state.host_len = 0;
}

/// BoringSSL certificate verification callback, installed only on
/// connections whose DaneState is armed. DANE-EE(3): the presented leaf
/// matching any usable TLSA record authenticates the connection; a
/// non-empty set with no match is a hard failure. Unusable/empty sets
/// never reach this callback (the state is not armed).
pub fn verifyCallback(store_ctx: *X509_STORE_CTX, arg: ?*anyopaque) callconv(.c) c_int {
    const state: *DaneState = @ptrCast(@alignCast(arg orelse return 0));
    if (!state.armed or state.count == 0) {
        // Not armed: preserve standard chain verification.
        return X509_verify_cert(store_ctx);
    }

    // curl clones the ssl_ctx callback onto its internal DoH sub-easys
    // (doh.c copies CURLOPT_SSL_CTX_FUNCTION/DATA), so this callback also
    // fires for the DoH endpoint's own TLS connection. Scope DANE strictly
    // to the armed hostname via SNI; every other connection keeps standard
    // chain verification.
    const sni: ?[*:0]const u8 = blk: {
        const raw = X509_STORE_CTX_get_ex_data(store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx()) orelse break :blk null;
        const ssl: *const SSL = @ptrCast(raw);
        break :blk SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    };
    const target = if (sni) |s| std.mem.eql(u8, std.mem.span(s), state.hostname()) else false;
    if (!target) {
        return X509_verify_cert(store_ctx);
    }

    const leaf = X509_STORE_CTX_get0_cert(store_ctx) orelse {
        X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    };

    for (state.recs[0..state.count]) |*rec| {
        if (matches(leaf, rec)) {
            const trust: []const u8 = if (state.verified) "verified spv channel" else "trusted doh channel";
            log.info(.http, "hns dane match", .{ .host = state.hostname(), .trust = trust });
            return 1;
        }
    }
    // Fail closed: record an explicit error so the post-handshake
    // verify-result check cannot read this as success.
    X509_STORE_CTX_set_error(store_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    log.warn(.http, "hns dane mismatch", .{ .host = state.hostname(), .records = state.count });
    return 0;
}

fn matches(leaf: *crypto.X509, rec: *const Rec) bool {
    var digest: [64]u8 = undefined;

    switch (rec.selector) {
        0 => { // full certificate DER
            var dlen: c_uint = 0;
            const md = if (rec.len == 64) crypto.EVP_sha512() else crypto.EVP_sha256();
            if (X509_digest(leaf, md, &digest, &dlen) != 1) return false;
            if (dlen != rec.len) return false;
        },
        1 => { // SubjectPublicKeyInfo DER
            const pubkey = X509_get_X509_PUBKEY(leaf) orelse return false;
            const need = i2d_X509_PUBKEY(pubkey, null);
            if (need <= 0 or need > 4096) return false;
            var spki_buf: [4096]u8 = undefined;
            var out: [*]u8 = &spki_buf;
            const got = i2d_X509_PUBKEY(pubkey, &out);
            if (got != need) return false;
            const spki = spki_buf[0..@intCast(got)];
            if (rec.len == 64) {
                std.crypto.hash.sha2.Sha512.hash(spki, digest[0..64], .{});
            } else {
                std.crypto.hash.sha2.Sha256.hash(spki, digest[0..32], .{});
            }
        },
        else => return false,
    }
    return std.mem.eql(u8, digest[0..rec.len], rec.hash[0..rec.len]);
}

// -- DNS wire helpers ------------------------------------------------------

pub const TYPE_A = 1;
pub const TYPE_AAAA = 28;
pub const TYPE_TLSA = 52;

pub fn buildQuery(buf: []u8, qname: []const u8, qtype: u16) ?[]const u8 {
    var w: usize = 0;
    // header: id 0, RD, one question
    const header = [_]u8{ 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    @memcpy(buf[0..12], &header);
    w = 12;
    if (!std.mem.eql(u8, qname, ".")) { // "." is the root: no labels
        var it = std.mem.splitScalar(u8, qname, '.');
        while (it.next()) |label| {
            if (label.len == 0 or label.len > 63) return null;
            if (w + 1 + label.len + 5 > buf.len) return null;
            buf[w] = @intCast(label.len);
            @memcpy(buf[w + 1 ..][0..label.len], label);
            w += 1 + label.len;
        }
    }
    buf[w] = 0;
    std.mem.writeInt(u16, buf[w + 1 ..][0..2], qtype, .big);
    std.mem.writeInt(u16, buf[w + 3 ..][0..2], 1, .big); // IN
    return buf[0 .. w + 5];
}

pub fn skipName(msg: []const u8, start: usize) ?usize {
    var o = start;
    while (o < msg.len) {
        const l = msg[o];
        if (l == 0) return o + 1;
        if (l & 0xc0 != 0) return o + 2;
        o += 1 + @as(usize, l);
    }
    return null;
}

/// Parse a DNS response, keeping usable DANE-EE(3) TLSA records.
pub fn parseTlsa(msg: []const u8, state: *DaneState) u8 {
    if (msg.len < 12) return 0;
    const flags = std.mem.readInt(u16, msg[2..4], .big);
    if (flags & 0xf != 0) return 0; // not NOERROR
    const qd = std.mem.readInt(u16, msg[4..6], .big);
    const an = std.mem.readInt(u16, msg[6..8], .big);

    var o: usize = 12;
    var i: usize = 0;
    while (i < qd) : (i += 1) {
        o = (skipName(msg, o) orelse return 0) + 4;
        if (o > msg.len) return 0;
    }

    var kept: u8 = 0;
    i = 0;
    while (i < an and kept < max_records) : (i += 1) {
        o = skipName(msg, o) orelse return 0;
        if (o + 10 > msg.len) return 0;
        const rtype = std.mem.readInt(u16, msg[o..][0..2], .big);
        const rdlen = std.mem.readInt(u16, msg[o + 8 ..][0..2], .big);
        o += 10;
        if (o + rdlen > msg.len) return 0;
        const rdata = msg[o .. o + rdlen];
        o += rdlen;

        if (rtype != TYPE_TLSA or rdata.len < 4) continue;
        const usage = rdata[0];
        const selector = rdata[1];
        const mtype = rdata[2];
        const assoc = rdata[3..];

        // Usable subset: DANE-EE(3) only, selectors 0/1, matching 0/1/2.
        if (usage != 3 or selector > 1 or mtype > 2) continue;

        var rec = &state.recs[kept];
        rec.selector = selector;
        rec.mtype = mtype;
        switch (mtype) {
            0 => { // full data, normalized to sha-256
                std.crypto.hash.sha2.Sha256.hash(assoc, rec.hash[0..32], .{});
                rec.len = 32;
            },
            1 => {
                if (assoc.len != 32) continue;
                @memcpy(rec.hash[0..32], assoc);
                rec.len = 32;
            },
            2 => {
                if (assoc.len != 64) continue;
                @memcpy(rec.hash[0..64], assoc);
                rec.len = 64;
            },
            else => continue,
        }
        kept += 1;
    }
    state.count = kept;
    return kept;
}

// -- blocking DoH fetch ----------------------------------------------------

const Response = struct {
    buf: [8192]u8 = undefined,
    len: usize = 0,
};

fn collect(ptr: [*]const u8, count: usize, size: usize, userp: *anyopaque) callconv(.c) usize {
    const resp: *Response = @ptrCast(@alignCast(userp));
    const n = count * size;
    const room = resp.buf.len - resp.len;
    const take = @min(n, room);
    @memcpy(resp.buf[resp.len..][0..take], ptr[0..take]);
    resp.len += take;
    return n; // over-cap bytes are discarded; a >8KB TLSA set is unusable
}

// One blocking GET against the DoH endpoint, TLS-verified against the same
// X509 store as every other transfer. Runs on the worker at connection
// setup; bounded by lookup_timeout_ms.
fn fetch(url: [:0]const u8, x509_store: *crypto.X509_STORE, resp: *Response) bool {
    const easy = libcurl.curl_easy_init() orelse return false;
    defer libcurl.curl_easy_cleanup(easy);

    libcurl.curl_easy_setopt(easy, .url, url.ptr) catch return false;
    libcurl.curl_easy_setopt(easy, .timeout_ms, lookup_timeout_ms) catch return false;
    libcurl.curl_easy_setopt(easy, .write_data, @as(?*anyopaque, resp)) catch return false;
    libcurl.curl_easy_setopt(easy, .write_function, @as(libcurl.CurlWriteFunction, collect)) catch return false;
    libcurl.curl_easy_setopt(easy, .ssl_ctx_function, &(struct {
        fn wrap(_: *libcurl.Curl, raw_ssl_ctx: *anyopaque, raw_store: *anyopaque) callconv(.c) libcurl.CurlCode {
            const ssl_ctx: *crypto.SSL_CTX = @ptrCast(raw_ssl_ctx);
            const store: *crypto.X509_STORE = @ptrCast(raw_store);
            if (crypto.SSL_CTX_set1_verify_cert_store(ssl_ctx, store) != 1) {
                return libcurl.CURLE.ABORTED_BY_CALLBACK;
            }
            return libcurl.CURLE.OK;
        }
    }).wrap) catch return false;
    libcurl.curl_easy_setopt(easy, .ssl_ctx_data, x509_store) catch return false;

    libcurl.curl_easy_perform(easy) catch return false;

    var code: c_long = 0;
    libcurl.curl_easy_getinfo(easy, .response_code, &code) catch return false;
    return code == 200 and resp.len >= 12;
}
