const std = @import("std");
const frontend = @import("runar_frontend");

pub const CompileCheckStage = enum {
    /// The source was refused before parsing, by the compiler's DoS input cap
    /// (`frontend.MAX_SOURCE_BYTES`). R-093: this check existed only in the
    /// CLI's pipeline, so the SDK accepted inputs the compiler refuses.
    input_limit,
    parse,
    validate,
    typecheck,
};

pub const CompileCheckResult = struct {
    stage: ?CompileCheckStage,
    messages: []const []const u8,

    pub fn ok(self: CompileCheckResult) bool {
        return self.stage == null;
    }

    pub fn deinit(self: CompileCheckResult, allocator: std.mem.Allocator) void {
        for (self.messages) |message| allocator.free(message);
        allocator.free(self.messages);
    }
};

pub fn compileCheckSource(
    allocator: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
) !CompileCheckResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const work_allocator = arena.allocator();

    // Pass 0 — the compiler's DoS input cap, the first thing `runPipeline` does.
    // R-093: this call did not exist, so a source the compiler refuses outright
    // reached the tokenizer here and came back "valid".
    frontend.assertSourceBytesUnderLimit(source) catch {
        const message = try std.fmt.allocPrint(
            allocator,
            "source is {d} bytes, which exceeds the {d}-byte limit",
            .{ source.len, frontend.MAX_SOURCE_BYTES },
        );
        errdefer allocator.free(message);
        const messages = try allocator.alloc([]const u8, 1);
        messages[0] = message;
        return .{ .stage = .input_limit, .messages = messages };
    };

    // Pass 1 — the CLI's guarded, format-dispatching parse. This used to be a
    // bare `frontend.parseZig`, which (a) skipped the fail-closed `@sighash` /
    // `@embedAlways` refusal and (b) ran the Zig parser whatever the file's
    // extension said. Both made this API's answer differ from `--source`'s on
    // the same bytes, which is the one thing a "is this valid Runar?" call must
    // never do.
    const parse_result = frontend.parseSource(work_allocator, source, file_name);
    if (parse_result.errors.len != 0) {
        return .{
            .stage = .parse,
            .messages = try duplicateMessages(allocator, parse_result.errors),
        };
    }

    const contract = parse_result.contract orelse {
        return .{
            .stage = .parse,
            .messages = try duplicateMessages(allocator, &.{ "no contract found" }),
        };
    };

    // Pass 2 — validate with the validator the SURFACE calls for. `.runar.zig`
    // relaxes the `super()` constructor requirement; no other surface does, and
    // hard-wiring `validateZig` here handed every other surface the relaxation.
    const validation = try frontend.validateForFile(work_allocator, contract, file_name);
    if (validation.errors.len != 0) {
        return .{
            .stage = .validate,
            .messages = try duplicateDiagnostics(allocator, validation.errors),
        };
    }

    const typecheck_result = try frontend.typeCheck(work_allocator, contract);
    if (typecheck_result.errors.len != 0) {
        return .{
            .stage = .typecheck,
            .messages = try duplicateMessages(allocator, typecheck_result.errors),
        };
    }

    return .{
        .stage = null,
        .messages = try allocator.alloc([]const u8, 0),
    };
}

pub fn compileCheckFile(
    allocator: std.mem.Allocator,
    file_path: []const u8,
) !CompileCheckResult {
    // The read bound is the compiler's own input cap, not a private 1 MiB one:
    // a 2 MiB contract the compiler accepts used to fail here with
    // `StreamTooLong` before `compileCheckSource` ever saw it (R-093). Reading
    // one byte past the cap lets `compileCheckSource` report the overrun as a
    // diagnostic rather than as a read error.
    const source = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, file_path, allocator, .limited(frontend.MAX_SOURCE_BYTES + 1));
    defer allocator.free(source);

    return compileCheckSource(allocator, source, file_path);
}

fn duplicateMessages(
    allocator: std.mem.Allocator,
    messages: []const []const u8,
) ![]const []const u8 {
    var out = try allocator.alloc([]const u8, messages.len);
    errdefer {
        for (out[0..messages.len]) |message| {
            if (message.len != 0) allocator.free(message);
        }
        allocator.free(out);
    }

    for (messages, 0..) |message, index| {
        out[index] = try allocator.dupe(u8, message);
    }
    return out;
}

fn duplicateDiagnostics(
    allocator: std.mem.Allocator,
    diagnostics: anytype,
) ![]const []const u8 {
    var out = try allocator.alloc([]const u8, diagnostics.len);
    errdefer {
        for (out[0..diagnostics.len]) |message| {
            if (message.len != 0) allocator.free(message);
        }
        allocator.free(out);
    }

    for (diagnostics, 0..) |diagnostic, index| {
        out[index] = try allocator.dupe(u8, diagnostic.message);
    }
    return out;
}

test "compileCheckSource accepts a valid contract" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const P2PKH = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    pubKeyHash: runar.Addr,
        \\
        \\    pub fn init(pubKeyHash: runar.Addr) P2PKH {
        \\        return .{ .pubKeyHash = pubKeyHash };
        \\    }
        \\
        \\    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        \\        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        \\        runar.assert(runar.checkSig(sig, pubKey));
        \\    }
        \\};
    ;

    const result = try compileCheckSource(std.testing.allocator, source, "P2PKH.runar.zig");
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.ok());
    try std.testing.expectEqual(@as(usize, 0), result.messages.len);
}

test "compileCheckSource reports validation failures" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Broken = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    owner: runar.PubKey,
        \\
        \\    pub fn init(owner: runar.PubKey) Broken {
        \\        return .{ .owner = owner };
        \\    }
        \\
        \\    pub fn unlock(self: *const Broken, sig: runar.Sig) void {
        \\        _ = self;
        \\        _ = sig;
        \\    }
        \\};
    ;

    const result = try compileCheckSource(std.testing.allocator, source, "Broken.runar.zig");
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(!result.ok());
    try std.testing.expectEqual(CompileCheckStage.validate, result.stage.?);
    try std.testing.expect(result.messages.len != 0);
}

test "compileCheckSource reports Zig constructor assignment failures" {
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Broken = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    owner: runar.PubKey,
        \\    amount: i64,
        \\
        \\    pub fn init(owner: runar.PubKey, amount: i64) Broken {
        \\        return .{ .owner = owner };
        \\    }
        \\
        \\    pub fn unlock(self: *const Broken) void {
        \\        runar.assert(self.amount > 0);
        \\    }
        \\};
    ;

    const result = try compileCheckSource(std.testing.allocator, source, "BrokenCtor.runar.zig");
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(!result.ok());
    try std.testing.expectEqual(CompileCheckStage.validate, result.stage.?);
    // TWO distinct diagnostics, both correct and both load-bearing: `amount` is
    // never assigned (so the property has no source), AND it is a dead
    // constructor parameter (so every later constructor argument would be
    // spliced into the wrong property slot). The bijection check is the
    // all-7-tier one added in 02-validate.ts / validator.{go,rs,py,rb} /
    // validate.zig; this expectation predated it and asserted a count of 1.
    try std.testing.expectEqual(@as(usize, 2), result.messages.len);
    try std.testing.expectEqualStrings("property must be assigned in the constructor", result.messages[0]);
    try std.testing.expect(std.mem.startsWith(u8, result.messages[1], "constructor parameter 'amount' does not initialise any property."));
}

// ---------------------------------------------------------------------------
// R-093 — the SDK's frontend check must apply the guards the CLI applies.
//
// `compileCheckSource` called `frontend.parseZig` — the RAW parser — so it ran
// neither the 4 MiB input cap nor the fail-closed `@sighash` / `@embedAlways`
// directive guard that `runPipeline` applies before and around its parse. The
// SDK's "is this valid Runar?" API therefore ACCEPTED sources the compiler
// REJECTS, which is the same shape as N-091 / R-085 (Java's `CompileCheck`
// green-lit invalid Runar by running a frontend chain the CLI did not; closed
// by `bca3bb4f`).
//
// Each test below asserts the DIAGNOSTIC, not merely "not ok" — a rejection
// test that only checks a boolean cannot tell a correct refusal from an
// unrelated one.
// ---------------------------------------------------------------------------

/// A valid `.runar.zig` contract, used as the body of every R-093 probe so the
/// only thing under test is the guard.
const R093_VALID_BODY =
    \\pub const P2PKH = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    pubKeyHash: runar.Addr,
    \\
    \\    pub fn init(pubKeyHash: runar.Addr) P2PKH {
    \\        return .{ .pubKeyHash = pubKeyHash };
    \\    }
    \\
    \\    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
    \\        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
    \\        runar.assert(runar.checkSig(sig, pubKey));
    \\    }
    \\};
;

test "R-093: compileCheckSource rejects an @sighash directive, as --source does" {
    const source =
        \\const runar = @import("runar");
        \\
        \\// @sighash ALL|FORKID
        \\
    ++ R093_VALID_BODY;

    const result = try compileCheckSource(std.testing.allocator, source, "Sighash.runar.zig");
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(!result.ok());
    try std.testing.expectEqual(CompileCheckStage.parse, result.stage.?);
    try std.testing.expectEqual(@as(usize, 1), result.messages.len);
    try std.testing.expectEqualStrings(
        frontend.SIGHASH_DIRECTIVE_ERROR,
        result.messages[0],
    );
}

test "R-093: compileCheckSource rejects an @embedAlways directive, as --source does" {
    const source =
        \\const runar = @import("runar");
        \\
        \\// @embedAlways
        \\
    ++ R093_VALID_BODY;

    const result = try compileCheckSource(std.testing.allocator, source, "EmbedAlways.runar.zig");
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(!result.ok());
    try std.testing.expectEqual(CompileCheckStage.parse, result.stage.?);
    try std.testing.expectEqual(@as(usize, 1), result.messages.len);
    try std.testing.expectEqualStrings(
        frontend.EMBED_ALWAYS_DIRECTIVE_ERROR,
        result.messages[0],
    );
}

test "R-093: compileCheckSource enforces the compiler's 4 MiB input cap" {
    const allocator = std.testing.allocator;

    const prefix =
        \\const runar = @import("runar");
        \\
        \\//
    ;
    const pad_len = frontend.MAX_SOURCE_BYTES + 1 - prefix.len - R093_VALID_BODY.len - 1;
    const pad = try allocator.alloc(u8, pad_len);
    @memset(pad, 'x');
    defer allocator.free(pad);
    const source = try std.mem.concat(allocator, u8, &.{ prefix, pad, "\n", R093_VALID_BODY });
    defer allocator.free(source);
    try std.testing.expect(source.len > frontend.MAX_SOURCE_BYTES);

    const result = try compileCheckSource(allocator, source, "Huge.runar.zig");
    defer result.deinit(allocator);

    try std.testing.expect(!result.ok());
    try std.testing.expectEqual(CompileCheckStage.input_limit, result.stage.?);
    try std.testing.expectEqual(@as(usize, 1), result.messages.len);
    try std.testing.expect(std.mem.indexOf(u8, result.messages[0], "exceeds") != null);
}

test "R-093: a source just under the cap is still accepted" {
    const allocator = std.testing.allocator;

    const prefix =
        \\const runar = @import("runar");
        \\
        \\//
    ;
    // One byte under the limit: the guard must be `>`, not `>=`.
    const pad_len = frontend.MAX_SOURCE_BYTES - prefix.len - R093_VALID_BODY.len - 1;
    const pad = try allocator.alloc(u8, pad_len);
    @memset(pad, 'x');
    defer allocator.free(pad);
    const source = try std.mem.concat(allocator, u8, &.{ prefix, pad, "\n", R093_VALID_BODY });
    defer allocator.free(source);
    try std.testing.expectEqual(frontend.MAX_SOURCE_BYTES, source.len);

    const result = try compileCheckSource(allocator, source, "Big.runar.zig");
    defer result.deinit(allocator);

    try std.testing.expect(result.ok());
}

test "R-093: compileCheckFile accepts a 2 MiB contract the compiler accepts" {
    const allocator = std.testing.allocator;

    // The old read bound was a private 1 MiB, so a contract between 1 and 4 MiB
    // failed here with `StreamTooLong` — a read error, not a diagnostic — while
    // `runar-zig --source` on the same file compiled it. Two MiB is inside the
    // compiler's cap and outside the old one.
    const prefix =
        \\const runar = @import("runar");
        \\
        \\//
    ;
    const target: usize = 2 * 1024 * 1024;
    const pad = try allocator.alloc(u8, target - prefix.len - R093_VALID_BODY.len - 1);
    @memset(pad, 'x');
    defer allocator.free(pad);
    const source = try std.mem.concat(allocator, u8, &.{ prefix, pad, "\n", R093_VALID_BODY });
    defer allocator.free(source);
    try std.testing.expectEqual(target, source.len);
    try std.testing.expect(source.len < frontend.MAX_SOURCE_BYTES);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "Big.runar.zig", .data = source });

    const full_path = try tmp.dir.realPathFileAlloc(std.testing.io, "Big.runar.zig", allocator);
    defer allocator.free(full_path);

    const result = try compileCheckFile(allocator, full_path);
    defer result.deinit(allocator);

    try std.testing.expect(result.ok());
}

test "compileCheckFile reads and checks a file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = "Simple.runar.zig",
        .data =
        \\const runar = @import("runar");
        \\
        \\pub const P2PKH = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    pubKeyHash: runar.Addr,
        \\
        \\    pub fn init(pubKeyHash: runar.Addr) P2PKH {
        \\        return .{ .pubKeyHash = pubKeyHash };
        \\    }
        \\
        \\    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        \\        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        \\        runar.assert(runar.checkSig(sig, pubKey));
        \\    }
        \\};
        ,
    });

    const full_path = try tmp.dir.realPathFileAlloc(std.testing.io, "Simple.runar.zig", std.testing.allocator);
    defer std.testing.allocator.free(full_path);

    const result = try compileCheckFile(std.testing.allocator, full_path);
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.ok());
}
