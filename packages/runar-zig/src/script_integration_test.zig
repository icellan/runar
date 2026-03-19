const std = @import("std");
const harness = @import("bsvz_runar_harness");
const frontend = @import("runar_frontend");

const key_one_private = [_]u8{0} ** 31 ++ [_]u8{1};
const key_two_private = [_]u8{0} ** 31 ++ [_]u8{2};

const key_one_pub_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const key_two_pub_hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const runar_root = "../..";
const compiler_dist_path = "packages/runar-compiler/dist/index.js";
const p2pkh_source =
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

const arithmetic_source =
    \\const runar = @import("runar");
    \\
    \\pub const Arithmetic = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    target: i64,
    \\
    \\    pub fn init(target: i64) Arithmetic {
    \\        return .{ .target = target };
    \\    }
    \\
    \\    pub fn verify(self: *const Arithmetic, a: i64, b: i64) void {
    \\        const sum = a + b;
    \\        const diff = a - b;
    \\        const prod = a * b;
    \\        const result = sum + diff + prod;
    \\        runar.assert(result == self.target);
    \\    }
    \\};
;

const if_else_source =
    \\const runar = @import("runar");
    \\
    \\pub const IfElse = struct {
    \\    pub const Contract = runar.SmartContract;
    \\
    \\    limit: i64,
    \\
    \\    pub fn init(limit: i64) IfElse {
    \\        return .{ .limit = limit };
    \\    }
    \\
    \\    pub fn check(self: *const IfElse, value: i64, mode: bool) void {
    \\        var result: i64 = 0;
    \\        if (mode) {
    \\            result = value + self.limit;
    \\        } else {
    \\            result = value - self.limit;
    \\        }
    \\        runar.assert(result > 0);
    \\    }
    \\};
;

fn accessOrSkip(rel_path: []const u8) !void {
    std.fs.cwd().access(rel_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
}

fn trimOwned(allocator: std.mem.Allocator, owned: []u8) ![]u8 {
    const trimmed = std.mem.trim(u8, owned, &std.ascii.whitespace);
    if (trimmed.ptr == owned.ptr and trimmed.len == owned.len) {
        return owned;
    }

    const copy = try allocator.dupe(u8, trimmed);
    allocator.free(owned);
    return copy;
}

fn encodeBase64Alloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(bytes.len));
    _ = encoder.encode(encoded, bytes);
    return encoded;
}

fn compileRunarScriptHex(
    allocator: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
    constructor_args_expr: []const u8,
) ![]u8 {
    const compiler_abs_rel = try std.fmt.allocPrint(allocator, "{s}/{s}", .{
        runar_root,
        compiler_dist_path,
    });
    defer allocator.free(compiler_abs_rel);
    try accessOrSkip(compiler_abs_rel);

    const source_b64 = try encodeBase64Alloc(allocator, source);
    defer allocator.free(source_b64);
    const file_name_b64 = try encodeBase64Alloc(allocator, file_name);
    defer allocator.free(file_name_b64);
    const args_expr_b64 = try encodeBase64Alloc(allocator, constructor_args_expr);
    defer allocator.free(args_expr_b64);

    const code = try std.fmt.allocPrint(allocator,
        \\(async () => {{
        \\  const {{ compile }} = await import('./{s}');
        \\  const source = Buffer.from('{s}', 'base64').toString('utf8');
        \\  const fileName = Buffer.from('{s}', 'base64').toString('utf8');
        \\  const constructorArgsExpr = Buffer.from('{s}', 'base64').toString('utf8');
        \\  const constructorArgs = Function('"use strict"; return (' + constructorArgsExpr + ');')();
        \\  const result = compile(source, {{ fileName, constructorArgs }});
        \\  if (!result.success || !result.scriptHex) {{
        \\    console.error(JSON.stringify(result));
        \\    process.exit(1);
        \\  }}
        \\  process.stdout.write(result.scriptHex);
        \\}})();
    , .{ compiler_dist_path, source_b64, file_name_b64, args_expr_b64 });
    defer allocator.free(code);

    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "node", "-e", code },
        .cwd = runar_root,
        .max_output_bytes = 4 * 1024 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound, error.CurrentWorkingDirectoryUnlinked => return error.SkipZigTest,
        else => return err,
    };
    defer allocator.free(run_result.stderr);

    switch (run_result.term) {
        .Exited => |code_value| {
            if (code_value != 0) {
                std.log.err("runar compile failed: {s}", .{run_result.stderr});
                allocator.free(run_result.stdout);
                return error.RunarCompileFailed;
            }
        },
        else => {
            allocator.free(run_result.stdout);
            return error.RunarCompileFailed;
        },
    }

    return trimOwned(allocator, run_result.stdout);
}

fn expectCompiledHexContains(
    allocator: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
    expected_fragments: []const []const u8,
) !void {
    const hex = try frontend.compileSourceToHex(allocator, source, file_name);
    defer allocator.free(hex);

    try std.testing.expect(hex.len > 0);
    for (expected_fragments) |fragment| {
        try std.testing.expect(std.mem.indexOf(u8, hex, fragment) != null);
    }
}

fn expectCaseOutcome(
    allocator: std.mem.Allocator,
    case: harness.Case,
    expected: harness.VerificationOutcome,
) !void {
    var traced = try harness.runCaseTraced(allocator, case);
    defer traced.deinit(allocator);

    const actual = traced.outcome();
    if (verificationOutcomesEqual(actual, expected)) {
        return;
    }

    var rendered = std.ArrayList(u8){};
    defer rendered.deinit(allocator);

    try rendered.writer(allocator).print("runar-zig harness mismatch: {s}\nactual=", .{case.name});
    try actual.writeDebug(rendered.writer(allocator));
    try rendered.writer(allocator).writeAll("\nexpected=");
    try expected.writeDebug(rendered.writer(allocator));
    try rendered.writer(allocator).writeByte('\n');
    try traced.writeDebug(rendered.writer(allocator));
    if (traced.failureStep()) |step| {
        try rendered.writer(allocator).print(
            "\nfailure_step: phase={s} opcode={s} offset={}",
            .{ step.phase.label(), step.opcodeName(), step.opcode_offset },
        );
    }
    try rendered.writer(allocator).writeByte('\n');

    std.debug.print("{s}", .{rendered.items});
    return error.TestExpectedEqual;
}

fn verificationOutcomesEqual(
    actual: harness.VerificationOutcome,
    expected: harness.VerificationOutcome,
) bool {
    return switch (actual) {
        .success => expected == .success,
        .false_result => expected == .false_result,
        .script_error => |actual_err| switch (expected) {
            .script_error => |expected_err| actual_err == expected_err,
            else => false,
        },
    };
}

test "compileSourceToHex produces output for P2PKH" {
    const allocator = std.testing.allocator;
    try expectCompiledHexContains(allocator, p2pkh_source, "P2PKH.runar.zig", &.{ "76", "a9", "ac" });
}

test "compileSourceToHex produces output for arithmetic contract" {
    const allocator = std.testing.allocator;
    try expectCompiledHexContains(allocator, arithmetic_source, "Arithmetic.runar.zig", &.{"93"});
}

test "compileSourceToHex produces output for if-else contract" {
    const allocator = std.testing.allocator;
    try expectCompiledHexContains(allocator, if_else_source, "IfElse.runar.zig", &.{ "63", "67" });
}

// Note: bounded-loop (while) is supported by the TS Zig parser but not
// the native Zig compiler parser, so we don't test it here.

test "compileSource returns full artifact JSON" {
    const allocator = std.testing.allocator;

    const result = try frontend.compileSource(allocator, p2pkh_source, "P2PKH.runar.zig");
    defer result.deinit(allocator);

    try std.testing.expect(result.script_hex.len > 0);
    try std.testing.expect(result.artifact_json != null);

    const json = result.artifact_json.?;
    // Artifact should be valid JSON with contract name and abi
    try std.testing.expect(std.mem.indexOf(u8, json, "\"contract\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"abi\"") != null);
}

test "compileSourceToHex rejects invalid source" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.ParseFailed,
        frontend.compileSourceToHex(allocator, "not valid zig", "bad.runar.zig"),
    );
}

test "representative Runar scripts execute through the shared bsvz harness" {
    const allocator = std.testing.allocator;
    const arithmetic_locking_script_hex = try compileRunarScriptHex(
        allocator,
        arithmetic_source,
        "Arithmetic.runar.zig",
        "{ target: 27n }",
    );
    defer allocator.free(arithmetic_locking_script_hex);
    const arithmetic_fail_locking_script_hex = try compileRunarScriptHex(
        allocator,
        arithmetic_source,
        "Arithmetic.runar.zig",
        "{ target: 1n }",
    );
    defer allocator.free(arithmetic_fail_locking_script_hex);
    const if_else_locking_script_hex = try compileRunarScriptHex(
        allocator,
        if_else_source,
        "IfElse.runar.zig",
        "{ limit: 10n }",
    );
    defer allocator.free(if_else_locking_script_hex);
    const p2pkh_locking_script_hex = try compileRunarScriptHex(
        allocator,
        p2pkh_source,
        "P2PKH.runar.zig",
        "{ pubKeyHash: '751e76e8199196d454941c45d1b3a323f1433bd6' }",
    );
    defer allocator.free(p2pkh_locking_script_hex);

    const cases = [_]harness.Case{
        .{
            .name = "runar arithmetic success",
            .locking_script_hex = arithmetic_locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .int = 3 },
                .{ .int = 7 },
            },
            .expect_success = true,
        },
        .{
            .name = "runar arithmetic fail",
            .locking_script_hex = arithmetic_fail_locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .int = 3 },
                .{ .int = 7 },
            },
            .expect_success = false,
        },
        .{
            .name = "runar if-else success",
            .locking_script_hex = if_else_locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .int = 15 },
                .{ .boolean = true },
            },
            .expect_success = true,
        },
        .{
            .name = "runar if-else fail",
            .locking_script_hex = if_else_locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .int = 5 },
                .{ .boolean = false },
            },
            .expect_success = false,
        },
        .{
            .name = "runar p2pkh success",
            .locking_script_hex = p2pkh_locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .signature = {} },
                .{ .hex = key_one_pub_hex },
            },
            .expect_success = true,
            .spend = .{ .signing_key = key_one_private },
        },
        .{
            .name = "runar p2pkh wrong-key fail",
            .locking_script_hex = p2pkh_locking_script_hex,
            .args = &[_]harness.PushValue{
                .{ .signature = {} },
                .{ .hex = key_two_pub_hex },
            },
            .expect_success = false,
            .spend = .{ .signing_key = key_two_private },
        },
    };

    for (cases) |case| {
        try expectCaseOutcome(
            allocator,
            case,
            if (case.expect_success) .success else .false_result,
        );
    }
}
