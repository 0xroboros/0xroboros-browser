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

// Handshake name resolution via DNS-over-HTTPS (Lane T).
//
// TRUSTED resolution: names are resolved by a remote DoH resolver the user
// does not verify. This lane never touches key material and never weakens
// TLS verification; HTTPS to Handshake names failing CA validation stays
// failing (DANE is Lane D).
//
// Interim by design: the shipped default below is a public community
// Handshake DoH resolver. At Lane S kickoff, local SPV verification (hnsd)
// becomes the default resolution path and DoH drops to fallback.

const std = @import("std");
const builtin = @import("builtin");
const lp = @import("lightpanda");

const Config = @import("../../Config.zig");
const libcurl = @import("../../sys/libcurl.zig");
const http = @import("../http.zig");
const IpFilter = @import("../IpFilter.zig");
const crypto = @import("../../sys/libcrypto.zig");

const log = lp.log;

/// Public community Handshake DoH resolver (hns_doh_loadbalancer,
/// multi-node). Verified live 2026-08-04. TRUSTED, not verified.
pub const default_url: [:0]const u8 = "https://hnsdoh.com/dns-query";

/// Second, independently operated public Handshake DoH resolver (Easy HNS).
/// Verified live 2026-08-04. Used automatically for the session when the
/// startup probe of `default_url` fails.
pub const fallback_url: [:0]const u8 = "https://dns.easyhns.com/dns-query";

/// RFC 8484 GET payload used by the startup probe: a base64url-encoded
/// wireformat A query for a known Handshake name (nathan.woodburn).
const probe_dns_param = "AAABAAABAAAAAAAABm5hdGhhbgh3b29kYnVybgAAAQAB";

/// Probe timeout. The probe runs once, at startup, before the connection
/// pool is built.
const probe_timeout_ms: c_long = 5000;

// Resolved once by `select` during Network startup (single-threaded);
// read-only afterwards via `effectiveUrl`.
var effective: ?[:0]const u8 = null;
var selected = false;

/// Resolve the effective DoH URL for this session. Called once from
/// Network.init before the connection pool is built. Explicit configuration
/// wins: a URL is used as-is, the literal `off` disables HNS resolution
/// entirely (plain OS resolution). With no configuration, the default
/// public endpoint is probed once; on failure the fallback endpoint is
/// used for the session.
pub fn select(config: *const Config, x509_store: *crypto.X509_STORE, ip_filter: ?*const IpFilter) void {
    if (selected) return;

    // The startup probe is a network call; tests must not depend on it.
    if (builtin.is_test) {
        selected = true;
        effective = null;
        return;
    }

    if (config.hnsDohUrl()) |url| {
        selected = true;
        if (std.mem.eql(u8, url, "off")) {
            effective = null;
            log.info(.http, "hns doh disabled", .{ .arg = "--hns_doh_url", .value = "off" });
        } else {
            effective = url;
            log.info(.http, "hns doh enabled", .{ .url = url, .trust = "trusted resolver, not verified" });
        }
        return;
    }

    // No explicit configuration: probe the default once. The probe runs
    // before `selected` is set so its own connection uses plain OS
    // resolution for the resolver's hostname.
    const ok = probe(config, x509_store, ip_filter);
    selected = true;
    if (ok) {
        effective = default_url;
        log.info(.http, "hns doh enabled", .{ .url = default_url, .trust = "trusted resolver, not verified" });
    } else {
        effective = fallback_url;
        // Default endpoint unreachable: use the fallback for this session.
        log.warn(.http, "hns doh fallback engaged", .{
            .default = default_url,
            .fallback = fallback_url,
        });
    }
}

/// The DoH URL transfer handles should apply, or null when HNS resolution
/// is disabled (or `select` has not run, e.g. the `version` command).
pub fn effectiveUrl() ?[:0]const u8 {
    return effective;
}

// One blocking RFC 8484 GET against `default_url`, reusing the standard
// Connection setup so TLS verification runs against the same X509 store as
// every other transfer. Success = HTTP 200.
fn probe(config: *const Config, x509_store: *crypto.X509_STORE, ip_filter: ?*const IpFilter) bool {
    var conn = http.Connection.init(x509_store, config, ip_filter) catch |err| {
        log.warn(.http, "hns doh probe setup failed", .{ .err = err });
        return false;
    };
    defer conn.deinit();

    conn.setURL(default_url ++ "?dns=" ++ probe_dns_param) catch return false;
    libcurl.curl_easy_setopt(conn._easy, .timeout_ms, probe_timeout_ms) catch return false;
    libcurl.curl_easy_perform(conn._easy) catch |err| {
        log.warn(.http, "hns doh probe failed", .{ .url = default_url, .err = err });
        return false;
    };

    var code: c_long = 0;
    libcurl.curl_easy_getinfo(conn._easy, .response_code, &code) catch return false;
    if (code != 200) {
        log.warn(.http, "hns doh probe failed", .{ .url = default_url, .status = code });
        return false;
    }
    return true;
}
