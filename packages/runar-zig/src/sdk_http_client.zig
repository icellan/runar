const std = @import("std");
const builtin = @import("builtin");
const woc_mod = @import("sdk_woc_provider.zig");
const gorilla_mod = @import("sdk_gorillapool.zig");
const rpc_mod = @import("sdk_rpc_provider.zig");
const provider_mod = @import("sdk_provider.zig");

// ---------------------------------------------------------------------------
// Production HTTP transports for runar-zig SDK providers.
//
// Each provider (WhatsOnChain, GorillaPool, RPC) accepts a pluggable
// HttpTransport callback. This module ships two concrete implementations:
//
//   CurlHttpTransport — wraps the system `curl` binary through
//     std.process.run, which under zig 0.16 requires a runtime std.Io
//     instance. The transport owns a std.Io.Threaded backend so callers
//     don't need to manage Io plumbing themselves. curl handles TLS,
//     redirects, timeouts, and basic auth with minimal zig-side code,
//     which makes it the most robust production path today.
//
//   StdHttpTransport — wraps std.http.Client over the same Threaded Io
//     backend. Pure-zig path. Suitable for platforms where zig 0.16's
//     TLS client is mature (Linux, macOS). Certificates come from
//     std.crypto.Certificate.Bundle.
//
// Both transports expose `wocTransport()`, `gorillaTransport()`, and
// `rpcTransport()` converter methods that return the provider-specific
// HttpTransport struct wired with `ctx` pointed back at the parent.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// CurlHttpTransport
// ---------------------------------------------------------------------------

pub const CurlHttpTransport = struct {
    allocator: std.mem.Allocator,
    threaded: *std.Io.Threaded,

    pub fn init(allocator: std.mem.Allocator) !*CurlHttpTransport {
        const threaded = try allocator.create(std.Io.Threaded);
        errdefer allocator.destroy(threaded);
        threaded.* = std.Io.Threaded.init(allocator, .{});
        errdefer threaded.deinit();

        const self = try allocator.create(CurlHttpTransport);
        self.* = .{ .allocator = allocator, .threaded = threaded };
        return self;
    }

    pub fn deinit(self: *CurlHttpTransport) void {
        self.threaded.deinit();
        const a = self.allocator;
        a.destroy(self.threaded);
        a.destroy(self);
    }

    fn runCurl(
        self: *CurlHttpTransport,
        allocator: std.mem.Allocator,
        argv: []const []const u8,
    ) ![]u8 {
        const res = std.process.run(allocator, self.threaded.io(), .{ .argv = argv }) catch return error.NetworkError;
        defer allocator.free(res.stderr);
        switch (res.term) {
            .exited => |code| if (code != 0) {
                allocator.free(res.stdout);
                return error.NetworkError;
            },
            else => {
                allocator.free(res.stdout);
                return error.NetworkError;
            },
        }
        return res.stdout;
    }

    fn wocGet(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
    ) provider_mod.ProviderError![]u8 {
        const self: *CurlHttpTransport = @ptrCast(@alignCast(ctx));
        const argv = [_][]const u8{
            "curl",              "-sS", "-f",
            "--connect-timeout", "10",  "--max-time",
            "60",                url,
        };
        return self.runCurl(allocator, &argv) catch provider_mod.ProviderError.NetworkError;
    }

    fn wocPost(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
        content_type: []const u8,
        body: []const u8,
    ) provider_mod.ProviderError![]u8 {
        const self: *CurlHttpTransport = @ptrCast(@alignCast(ctx));
        const header = std.fmt.allocPrint(allocator, "Content-Type: {s}", .{content_type}) catch return provider_mod.ProviderError.OutOfMemory;
        defer allocator.free(header);
        const argv = [_][]const u8{
            "curl",              "-sS", "-f",
            "--connect-timeout", "10",  "--max-time",  "60",
            "-X",                "POST",
            "-H",                header,
            "-d",                body,
            url,
        };
        return self.runCurl(allocator, &argv) catch provider_mod.ProviderError.NetworkError;
    }

    pub fn wocTransport(self: *CurlHttpTransport) woc_mod.HttpTransport {
        return .{ .ctx = @ptrCast(self), .get = wocGet, .post = wocPost };
    }

    pub fn gorillaTransport(self: *CurlHttpTransport) gorilla_mod.HttpTransport {
        return .{ .ctx = @ptrCast(self), .get = wocGet, .post = wocPost };
    }

    fn rpcPost(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
        user: []const u8,
        pass: []const u8,
        body: []const u8,
    ) rpc_mod.RPCError![]u8 {
        const self: *CurlHttpTransport = @ptrCast(@alignCast(ctx));
        const userpass = std.fmt.allocPrint(allocator, "{s}:{s}", .{ user, pass }) catch return rpc_mod.RPCError.OutOfMemory;
        defer allocator.free(userpass);
        const argv = [_][]const u8{
            "curl",              "-sS", "-f",
            "--connect-timeout", "10",  "--max-time",   "60",
            "-X",                "POST",
            "-u",                userpass,
            "-H",                "Content-Type: application/json",
            "-d",                body,
            url,
        };
        return self.runCurl(allocator, &argv) catch rpc_mod.RPCError.TransportError;
    }

    pub fn rpcTransport(self: *CurlHttpTransport) rpc_mod.HttpTransport {
        return .{ .ctx = @ptrCast(self), .post = rpcPost };
    }
};

// ---------------------------------------------------------------------------
// StdHttpTransport — pure-zig HTTP transport wrapping std.http.Client.
// ---------------------------------------------------------------------------

pub const StdHttpTransport = struct {
    allocator: std.mem.Allocator,
    threaded: *std.Io.Threaded,
    client: *std.http.Client,

    pub fn init(allocator: std.mem.Allocator) !*StdHttpTransport {
        const threaded = try allocator.create(std.Io.Threaded);
        errdefer allocator.destroy(threaded);
        threaded.* = std.Io.Threaded.init(allocator, .{});
        errdefer threaded.deinit();

        const client = try allocator.create(std.http.Client);
        errdefer allocator.destroy(client);
        client.* = .{ .allocator = allocator, .io = threaded.io() };
        errdefer client.deinit();

        const self = try allocator.create(StdHttpTransport);
        self.* = .{ .allocator = allocator, .threaded = threaded, .client = client };
        return self;
    }

    pub fn deinit(self: *StdHttpTransport) void {
        self.client.deinit();
        self.allocator.destroy(self.client);
        self.threaded.deinit();
        self.allocator.destroy(self.threaded);
        const a = self.allocator;
        a.destroy(self);
    }

    fn doFetch(
        self: *StdHttpTransport,
        allocator: std.mem.Allocator,
        method: std.http.Method,
        url: []const u8,
        payload: ?[]const u8,
        extra_headers: []const std.http.Header,
    ) ![]u8 {
        var buf: std.Io.Writer.Allocating = .init(allocator);
        defer buf.deinit();
        const res = try self.client.fetch(.{
            .location = .{ .url = url },
            .method = method,
            .payload = payload,
            .extra_headers = extra_headers,
            .response_writer = &buf.writer,
        });
        const code: u16 = @intFromEnum(res.status);
        if (code < 200 or code >= 300) return error.NetworkError;
        return buf.toOwnedSlice();
    }

    fn wocGet(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
    ) provider_mod.ProviderError![]u8 {
        const self: *StdHttpTransport = @ptrCast(@alignCast(ctx));
        return self.doFetch(allocator, .GET, url, null, &.{}) catch |err| switch (err) {
            error.OutOfMemory => provider_mod.ProviderError.OutOfMemory,
            else => provider_mod.ProviderError.NetworkError,
        };
    }

    fn wocPost(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
        content_type: []const u8,
        body: []const u8,
    ) provider_mod.ProviderError![]u8 {
        const self: *StdHttpTransport = @ptrCast(@alignCast(ctx));
        const headers = [_]std.http.Header{.{ .name = "Content-Type", .value = content_type }};
        return self.doFetch(allocator, .POST, url, body, &headers) catch |err| switch (err) {
            error.OutOfMemory => provider_mod.ProviderError.OutOfMemory,
            else => provider_mod.ProviderError.NetworkError,
        };
    }

    pub fn wocTransport(self: *StdHttpTransport) woc_mod.HttpTransport {
        return .{ .ctx = @ptrCast(self), .get = wocGet, .post = wocPost };
    }

    pub fn gorillaTransport(self: *StdHttpTransport) gorilla_mod.HttpTransport {
        return .{ .ctx = @ptrCast(self), .get = wocGet, .post = wocPost };
    }

    fn rpcPost(
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        url: []const u8,
        user: []const u8,
        pass: []const u8,
        body: []const u8,
    ) rpc_mod.RPCError![]u8 {
        const self: *StdHttpTransport = @ptrCast(@alignCast(ctx));
        var joined_buf: [512]u8 = undefined;
        const joined = std.fmt.bufPrint(&joined_buf, "{s}:{s}", .{ user, pass }) catch return rpc_mod.RPCError.OutOfMemory;
        const b64_len = std.base64.standard.Encoder.calcSize(joined.len);
        const b64_buf = allocator.alloc(u8, b64_len) catch return rpc_mod.RPCError.OutOfMemory;
        defer allocator.free(b64_buf);
        const b64 = std.base64.standard.Encoder.encode(b64_buf, joined);
        const auth_header = std.fmt.allocPrint(allocator, "Basic {s}", .{b64}) catch return rpc_mod.RPCError.OutOfMemory;
        defer allocator.free(auth_header);
        const headers = [_]std.http.Header{
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "Authorization", .value = auth_header },
        };
        return self.doFetch(allocator, .POST, url, body, &headers) catch |err| switch (err) {
            error.OutOfMemory => rpc_mod.RPCError.OutOfMemory,
            else => rpc_mod.RPCError.TransportError,
        };
    }

    pub fn rpcTransport(self: *StdHttpTransport) rpc_mod.HttpTransport {
        return .{ .ctx = @ptrCast(self), .post = rpcPost };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn liveHttpEnabled() bool {
    // std.testing.environ is the test runner's pre-populated env block; it
    // avoids a libc dependency that std.c.getenv would force the build to
    // link. Only referenced from a test block so the testing module is
    // always available where this is called from.
    const v = std.testing.environ.getPosix("RUN_LIVE_HTTP") orelse return false;
    return std.mem.eql(u8, v, "1");
}

test "CurlHttpTransport init and deinit round-trip" {
    const t = try CurlHttpTransport.init(testing.allocator);
    defer t.deinit();
    try testing.expect(@intFromPtr(t.threaded) != 0);
}

test "CurlHttpTransport converters produce HttpTransport structs" {
    const t = try CurlHttpTransport.init(testing.allocator);
    defer t.deinit();
    const woc = t.wocTransport();
    const g = t.gorillaTransport();
    const r = t.rpcTransport();
    try testing.expect(woc.ctx == @as(*anyopaque, @ptrCast(t)));
    try testing.expect(g.ctx == @as(*anyopaque, @ptrCast(t)));
    try testing.expect(r.ctx == @as(*anyopaque, @ptrCast(t)));
}

test "CurlHttpTransport.runCurl exits cleanly with --version" {
    const t = try CurlHttpTransport.init(testing.allocator);
    defer t.deinit();
    const argv = [_][]const u8{ "curl", "--version" };
    const out = try t.runCurl(testing.allocator, &argv);
    defer testing.allocator.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "curl ") != null);
}

test "StdHttpTransport init and deinit round-trip" {
    const t = try StdHttpTransport.init(testing.allocator);
    defer t.deinit();
    try testing.expect(@intFromPtr(t.client) != 0);
    try testing.expect(@intFromPtr(t.threaded) != 0);
}

test "StdHttpTransport converters produce HttpTransport structs" {
    const t = try StdHttpTransport.init(testing.allocator);
    defer t.deinit();
    const woc = t.wocTransport();
    const g = t.gorillaTransport();
    const r = t.rpcTransport();
    try testing.expect(woc.ctx == @as(*anyopaque, @ptrCast(t)));
    try testing.expect(g.ctx == @as(*anyopaque, @ptrCast(t)));
    try testing.expect(r.ctx == @as(*anyopaque, @ptrCast(t)));
}

test "CurlHttpTransport live GET hits httpbin" {
    if (!liveHttpEnabled()) return error.SkipZigTest;
    const t = try CurlHttpTransport.init(testing.allocator);
    defer t.deinit();
    const woc = t.wocTransport();
    const body = try woc.get(woc.ctx, testing.allocator, "https://httpbin.org/get");
    defer testing.allocator.free(body);
    try testing.expect(std.mem.indexOf(u8, body, "httpbin.org") != null);
}

test "StdHttpTransport live GET hits httpbin" {
    if (!liveHttpEnabled()) return error.SkipZigTest;
    const t = try StdHttpTransport.init(testing.allocator);
    defer t.deinit();
    const woc = t.wocTransport();
    const body = try woc.get(woc.ctx, testing.allocator, "https://httpbin.org/get");
    defer testing.allocator.free(body);
    try testing.expect(std.mem.indexOf(u8, body, "httpbin.org") != null);
}
