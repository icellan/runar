const std = @import("std");
const frontend = @import("runar_frontend");

pub const CompileCheckStage = enum {
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

    const parse_result = frontend.parseZig(work_allocator, source, file_name);
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

    const validation = try frontend.validateContract(work_allocator, contract);
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
    const source = try std.fs.cwd().readFileAlloc(allocator, file_path, 1024 * 1024);
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
    try std.testing.expectEqual(@as(usize, 1), result.messages.len);
    try std.testing.expectEqualStrings("property must be assigned in the constructor", result.messages[0]);
}

test "compileCheckFile reads and checks a file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
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

    const full_path = try tmp.dir.realpathAlloc(std.testing.allocator, "Simple.runar.zig");
    defer std.testing.allocator.free(full_path);

    const result = try compileCheckFile(std.testing.allocator, full_path);
    defer result.deinit(std.testing.allocator);

    try std.testing.expect(result.ok());
}
