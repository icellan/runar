// ---------------------------------------------------------------------------
// sdk_wallet_client_integration_test.zig — live BRC-100 WalletClient round-trip.
//
// Mirrors integration/ruby/spec/wallet_client_spec.rb. Environment-gated:
// runs only when RUNAR_WALLET_ENDPOINT is set to the base URL of a BRC-100
// JSON-over-HTTP wallet endpoint. When unset, the test is skipped cleanly so
// local + CI runs stay green without any wallet setup.
//
// Optional env:
//   RUNAR_WALLET_ENDPOINT — base URL, required to actually run
//   RUNAR_WALLET_AUTH     — bearer token, optional
//   RUNAR_WALLET_BASKET   — basket name, default "runar-integration-test"
//
// Asserts:
//   * getPublicKey returns a 33-byte compressed pubkey (66 hex chars,
//     prefix 02/03).
//   * listOutputs returns an array (possibly empty); each entry exposes at
//     least one of outpoint / satoshis / lockingScript.
//
// Implementation: shell-out to curl through std.process.run, mirroring the
// CurlHttpTransport pattern used elsewhere in the SDK.
// ---------------------------------------------------------------------------

const std = @import("std");
const testing = std.testing;

fn envValue(name: []const u8) ?[]const u8 {
    return std.testing.environ.getPosix(name);
}

const PostError = error{
    Curl,
    Http,
    OutOfMemory,
};

fn curlPost(
    allocator: std.mem.Allocator,
    url: []const u8,
    body: []const u8,
    auth_token: ?[]const u8,
) PostError![]u8 {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();

    var argv = std.ArrayListUnmanaged([]const u8).empty;
    defer argv.deinit(allocator);

    argv.appendSlice(allocator, &.{
        "curl",              "-sS", "-f",
        "--connect-timeout", "10",  "--max-time",   "30",
        "-X",                "POST",
        "-H",                "Content-Type: application/json",
        "-d",                body,
    }) catch return PostError.OutOfMemory;

    var auth_header_buf: ?[]u8 = null;
    defer if (auth_header_buf) |b| allocator.free(b);
    if (auth_token) |tok| {
        const h = std.fmt.allocPrint(allocator, "Authorization: Bearer {s}", .{tok}) catch
            return PostError.OutOfMemory;
        auth_header_buf = h;
        argv.append(allocator, "-H") catch return PostError.OutOfMemory;
        argv.append(allocator, h) catch return PostError.OutOfMemory;
    }

    argv.append(allocator, url) catch return PostError.OutOfMemory;

    const res = std.process.run(allocator, threaded.io(), .{ .argv = argv.items }) catch {
        return PostError.Curl;
    };
    defer allocator.free(res.stderr);
    switch (res.term) {
        .exited => |code| if (code != 0) {
            allocator.free(res.stdout);
            return PostError.Http;
        },
        else => {
            allocator.free(res.stdout);
            return PostError.Curl;
        },
    }
    return res.stdout;
}

fn jsonString(value: std.json.Value, key: []const u8) ?[]const u8 {
    if (value != .object) return null;
    const v = value.object.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

test "BRC-100 WalletClient live endpoint round-trip" {
    const endpoint = envValue("RUNAR_WALLET_ENDPOINT") orelse return error.SkipZigTest;
    if (endpoint.len == 0) return error.SkipZigTest;

    const allocator = testing.allocator;
    const auth_token = envValue("RUNAR_WALLET_AUTH");
    const basket = envValue("RUNAR_WALLET_BASKET") orelse "runar-integration-test";

    var trimmed_end = endpoint.len;
    while (trimmed_end > 0 and endpoint[trimmed_end - 1] == '/') : (trimmed_end -= 1) {}
    const trimmed = endpoint[0..trimmed_end];

    // 1. getPublicKey: must return a 33-byte compressed secp256k1 key.
    {
        const url = try std.fmt.allocPrint(allocator, "{s}/getPublicKey", .{trimmed});
        defer allocator.free(url);
        const body =
            \\{"protocolID":[2,"runar integration"],"keyID":"1"}
        ;
        const resp_bytes = try curlPost(allocator, url, body, auth_token);
        defer allocator.free(resp_bytes);

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp_bytes, .{});
        defer parsed.deinit();
        const pub_key = jsonString(parsed.value, "publicKey") orelse
            jsonString(parsed.value, "publicKeyHex") orelse {
            std.debug.print("getPublicKey response missing publicKey: {s}\n", .{resp_bytes});
            return error.TestUnexpectedResult;
        };
        try testing.expectEqual(@as(usize, 66), pub_key.len);
        const prefix = pub_key[0..2];
        try testing.expect(std.mem.eql(u8, prefix, "02") or std.mem.eql(u8, prefix, "03"));
        for (pub_key) |c| {
            const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
            try testing.expect(is_hex);
        }
    }

    // 2. listOutputs: must return an array (possibly empty).
    {
        const url = try std.fmt.allocPrint(allocator, "{s}/listOutputs", .{trimmed});
        defer allocator.free(url);
        const body = try std.fmt.allocPrint(
            allocator,
            "{{\"basket\":\"{s}\",\"tags\":[],\"limit\":10}}",
            .{basket},
        );
        defer allocator.free(body);
        const resp_bytes = try curlPost(allocator, url, body, auth_token);
        defer allocator.free(resp_bytes);

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp_bytes, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return error.TestUnexpectedResult;
        const outputs_val = parsed.value.object.get("outputs") orelse return; // allow missing
        if (outputs_val != .array) return error.TestUnexpectedResult;
        for (outputs_val.array.items) |out| {
            try testing.expect(out == .object);
            const has_outpoint = out.object.get("outpoint") != null;
            const has_satoshis = out.object.get("satoshis") != null;
            const has_locking = out.object.get("lockingScript") != null;
            try testing.expect(has_outpoint or has_satoshis or has_locking);
        }
    }
}
