//! Intent sub-covenant intrinsics tests (BSVM Phase 13) — Zig tier.
//!
//! Mirrors `compilers/go/frontend/intent_intrinsics_test.go`. Exercises the
//! three witness-bridge intrinsics — extractPrevOutputScript,
//! requireOutputP2PKH, currentBlockHeight — end-to-end through the Zig
//! pipeline: parse_go -> validate -> typecheck -> anf_lower.

const std = @import("std");
const parse_go = @import("parse_go.zig");
const typecheck = @import("typecheck.zig");
const anf_lower = @import("anf_lower.zig");
const types = @import("../ir/types.zig");

const Allocator = std.mem.Allocator;
const ANFMethod = types.ANFMethod;

// ============================================================================
// Helpers (mirror Go's mustLowerGoSource / expectIntrinsicTypeError)
// ============================================================================

/// Parse, validate, typecheck, and ANF-lower a Go-DSL source string. Returns
/// the lowered methods. Caller frees via the arena allocator passed in.
fn mustLowerGoSource(allocator: Allocator, source: []const u8) ![]const ANFMethod {
    const parse_result = parse_go.parseGo(allocator, source, "Test.runar.go");
    if (parse_result.errors.len > 0) {
        std.debug.print("parse errors: ", .{});
        for (parse_result.errors) |e| std.debug.print("{s}; ", .{e});
        std.debug.print("\n", .{});
        return error.ParseFailed;
    }
    const contract = parse_result.contract orelse return error.NoContract;

    const tc_result = try typecheck.typeCheck(allocator, contract);
    if (tc_result.errors.len > 0) {
        std.debug.print("typecheck errors: ", .{});
        for (tc_result.errors) |e| std.debug.print("{s}; ", .{e});
        std.debug.print("\n", .{});
        return error.TypeCheckFailed;
    }

    const program = try anf_lower.lowerToANF(allocator, contract);
    return program.methods;
}

/// Assert that the source produces a typecheck error containing `substr`.
fn expectIntrinsicTypeError(allocator: Allocator, source: []const u8, substr: []const u8) !void {
    const parse_result = parse_go.parseGo(allocator, source, "Test.runar.go");
    if (parse_result.errors.len > 0) return error.UnexpectedParseErrors;
    const contract = parse_result.contract orelse return error.NoContract;

    const tc_result = try typecheck.typeCheck(allocator, contract);
    for (tc_result.errors) |e| {
        if (std.mem.indexOf(u8, e, substr) != null) return;
    }
    std.debug.print("expected typecheck error containing '{s}', got: ", .{substr});
    for (tc_result.errors) |e| std.debug.print("[{s}] ", .{e});
    std.debug.print("\n", .{});
    return error.ExpectedErrorMissing;
}

fn findMethod(methods: []const ANFMethod, name: []const u8) ?*const ANFMethod {
    for (methods) |*m| {
        if (std.mem.eql(u8, m.name, name)) return m;
    }
    return null;
}

fn paramExists(method: *const ANFMethod, name: []const u8) bool {
    for (method.params) |p| {
        if (std.mem.eql(u8, p.name, name)) return true;
    }
    return false;
}

fn countParam(method: *const ANFMethod, name: []const u8) usize {
    var n: usize = 0;
    for (method.params) |p| {
        if (std.mem.eql(u8, p.name, name)) n += 1;
    }
    return n;
}

// ============================================================================
// extractPrevOutputScript
// ============================================================================

test "intent: extractPrevOutputScript auto-injects witness param" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type IntentCov struct {
        \\    runar.StatefulSmartContract
        \\    StateCovScriptHash runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *IntentCov) CoSpend() {
        \\    stateCovScript := runar.ExtractPrevOutputScript(0, c.StateCovScriptHash)
        \\    _ = stateCovScript
        \\}
    ;

    const methods = try mustLowerGoSource(allocator, source);
    const m = findMethod(methods, "coSpend") orelse return error.MethodNotFound;
    try std.testing.expect(paramExists(m, "_prevOutScript_0"));
    try std.testing.expect(paramExists(m, "txPreimage"));
}

test "intent: extractPrevOutputScript two indices produce two params" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type IntentCov struct {
        \\    runar.StatefulSmartContract
        \\    H0 runar.ByteString `runar:"readonly"`
        \\    H1 runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *IntentCov) CoSpend() {
        \\    a := runar.ExtractPrevOutputScript(0, c.H0)
        \\    b := runar.ExtractPrevOutputScript(1, c.H1)
        \\    _ = a
        \\    _ = b
        \\}
    ;

    const methods = try mustLowerGoSource(allocator, source);
    const m = findMethod(methods, "coSpend") orelse return error.MethodNotFound;
    try std.testing.expect(paramExists(m, "_prevOutScript_0"));
    try std.testing.expect(paramExists(m, "_prevOutScript_1"));
}

test "intent: extractPrevOutputScript same index is idempotent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type IntentCov struct {
        \\    runar.StatefulSmartContract
        \\    H0 runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *IntentCov) CoSpend() {
        \\    a := runar.ExtractPrevOutputScript(0, c.H0)
        \\    b := runar.ExtractPrevOutputScript(0, c.H0)
        \\    _ = a
        \\    _ = b
        \\}
    ;

    const methods = try mustLowerGoSource(allocator, source);
    const m = findMethod(methods, "coSpend") orelse return error.MethodNotFound;
    try std.testing.expectEqual(@as(usize, 1), countParam(m, "_prevOutScript_0"));
}

test "intent: extractPrevOutputScript non-literal index errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type IntentCov struct {
        \\    runar.StatefulSmartContract
        \\    H0 runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *IntentCov) CoSpend(idx runar.Bigint) {
        \\    _ = runar.ExtractPrevOutputScript(idx, c.H0)
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "must be an integer literal");
}

// ============================================================================
// requireOutputP2PKH
// ============================================================================

test "intent: requireOutputP2PKH auto-injects _serialisedOutputs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    BondPKH runar.ByteString `runar:"readonly"`
        \\    Bond    runar.Bigint     `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) PayBond() {
        \\    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
        \\}
    ;

    const methods = try mustLowerGoSource(allocator, source);
    const m = findMethod(methods, "payBond") orelse return error.MethodNotFound;
    try std.testing.expect(paramExists(m, "_serialisedOutputs"));
}

test "intent: requireOutputP2PKH multiple calls one _serialisedOutputs param" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    BondPKH runar.ByteString `runar:"readonly"`
        \\    Bond    runar.Bigint     `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) PayMulti() {
        \\    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
        \\    runar.RequireOutputP2PKH(1, c.BondPKH, c.Bond)
        \\}
    ;

    const methods = try mustLowerGoSource(allocator, source);
    const m = findMethod(methods, "payMulti") orelse return error.MethodNotFound;
    try std.testing.expectEqual(@as(usize, 1), countParam(m, "_serialisedOutputs"));
}

test "intent: requireOutputP2PKH non-literal index errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    BondPKH runar.ByteString `runar:"readonly"`
        \\    Bond    runar.Bigint     `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) PayBond(idx runar.Bigint) {
        \\    runar.RequireOutputP2PKH(idx, c.BondPKH, c.Bond)
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "must be an integer literal");
}

// ============================================================================
// currentBlockHeight
// ============================================================================

test "intent: currentBlockHeight desugars to extractLocktime" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    Deadline runar.Bigint `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) Spend() {
        \\    h := runar.CurrentBlockHeight()
        \\    runar.Assert(h <= c.Deadline)
        \\}
    ;

    const methods = try mustLowerGoSource(allocator, source);
    const m = findMethod(methods, "spend") orelse return error.MethodNotFound;
    var saw_extract_locktime = false;
    for (m.body) |b| {
        switch (b.value) {
            .call => |call| {
                if (std.mem.eql(u8, call.func, "extractLocktime")) {
                    saw_extract_locktime = true;
                    break;
                }
            },
            else => {},
        }
    }
    try std.testing.expect(saw_extract_locktime);
}

test "intent: currentBlockHeight stateless contract errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Sl struct {
        \\    runar.SmartContract
        \\    Deadline runar.Bigint `runar:"readonly"`
        \\}
        \\
        \\func (c *Sl) Spend() bool {
        \\    h := runar.CurrentBlockHeight()
        \\    return h > c.Deadline
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "StatefulSmartContract");
}

// ============================================================================
// Crit-2 — extractPrevOutputScript prefix-hash 3-arg form
// ============================================================================

test "intent: extractPrevOutputScript prefix form lowers with substr" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type IntentTemplate struct {
        \\    runar.StatefulSmartContract
        \\    ExpectedPolicyPrefixHash runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *IntentTemplate) Bind() {
        \\    s := runar.ExtractPrevOutputScript(0, c.ExpectedPolicyPrefixHash, 600)
        \\    _ = s
        \\}
    ;

    const methods = try mustLowerGoSource(allocator, source);
    const m = findMethod(methods, "bind") orelse return error.MethodNotFound;

    // Expect a substr call inside the method body whose first arg is the
    // load_param ref for _prevOutScript_0. Walk the body looking for a
    // 3-arg `substr` call whose first arg resolves to that load_param.
    var saw_prefix_substr = false;
    for (m.body, 0..) |b, i| {
        switch (b.value) {
            .call => |call| {
                if (std.mem.eql(u8, call.func, "substr") and call.args.len == 3) {
                    const ref = call.args[0];
                    var j: usize = 0;
                    while (j < i) : (j += 1) {
                        if (std.mem.eql(u8, m.body[j].name, ref)) {
                            switch (m.body[j].value) {
                                .load_param => |lp| {
                                    if (std.mem.eql(u8, lp.name, "_prevOutScript_0")) {
                                        saw_prefix_substr = true;
                                    }
                                },
                                else => {},
                            }
                        }
                    }
                    if (saw_prefix_substr) break;
                }
            },
            else => {},
        }
    }
    try std.testing.expect(saw_prefix_substr);
}

test "intent: extractPrevOutputScript prefix form non-literal prefixLen errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    H runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) Bind(n runar.Bigint) {
        \\    _ = runar.ExtractPrevOutputScript(0, c.H, n)
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "prefixLen) must be an integer literal");
}

test "intent: extractPrevOutputScript too many args errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    H runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) Bind() {
        \\    _ = runar.ExtractPrevOutputScript(0, c.H, 600, 999)
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "expects 2 or 3 arguments");
}

// ============================================================================
// Crit-3 — requireOutputP2PKH + addDataOutput mix rejection
// ============================================================================

test "intent: requireOutputP2PKH mixed with addDataOutput errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    BondPKH runar.ByteString `runar:"readonly"`
        \\    Bond    runar.Bigint     `runar:"readonly"`
        \\    Tag     runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) PayBondAndAnnounce() {
        \\    c.AddDataOutput(0, c.Tag)
        \\    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "mixes requireOutputP2PKH() with addDataOutput()");
}

test "intent: requireOutputP2PKH without addDataOutput ok" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    BondPKH runar.ByteString `runar:"readonly"`
        \\    Bond    runar.Bigint     `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) PayBond() {
        \\    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
        \\}
    ;

    _ = try mustLowerGoSource(allocator, source);
}

// ============================================================================
// R-2 — index-literal bounds on extractPrevOutputScript / requireOutputP2PKH
// ============================================================================

test "intent R-2: requireOutputP2PKH negative index errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    BondPKH runar.ByteString `runar:"readonly"`
        \\    Bond    runar.Bigint     `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) PayBond() {
        \\    runar.RequireOutputP2PKH(-1, c.BondPKH, c.Bond)
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "must be >= 0");
}

test "intent R-2: requireOutputP2PKH index over 1000 errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    BondPKH runar.ByteString `runar:"readonly"`
        \\    Bond    runar.Bigint     `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) PayBond() {
        \\    runar.RequireOutputP2PKH(1001, c.BondPKH, c.Bond)
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "bound to <= 1000");
}

test "intent R-2: requireOutputP2PKH index 1000 is allowed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    BondPKH runar.ByteString `runar:"readonly"`
        \\    Bond    runar.Bigint     `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) PayBond() {
        \\    runar.RequireOutputP2PKH(1000, c.BondPKH, c.Bond)
        \\}
    ;

    _ = try mustLowerGoSource(allocator, source);
}

test "intent R-2: extractPrevOutputScript negative index errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type IntentCov struct {
        \\    runar.StatefulSmartContract
        \\    H0 runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *IntentCov) CoSpend() {
        \\    s := runar.ExtractPrevOutputScript(-1, c.H0)
        \\    _ = s
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "must be >= 0");
}

test "intent R-2: extractPrevOutputScript large index is allowed (no upper bound)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // R-2 only bounds requireOutputP2PKH at <= 1000.
    // extractPrevOutputScript only requires idx >= 0.
    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type IntentCov struct {
        \\    runar.StatefulSmartContract
        \\    H0 runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *IntentCov) CoSpend() {
        \\    s := runar.ExtractPrevOutputScript(5000, c.H0)
        \\    _ = s
        \\}
    ;

    _ = try mustLowerGoSource(allocator, source);
}

// ============================================================================
// R-4 — prefixLen-literal bounds on extractPrevOutputScript 3-arg form
// ============================================================================

test "intent R-4: extractPrevOutputScript prefixLen < 32 errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    H runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) Bind() {
        \\    s := runar.ExtractPrevOutputScript(0, c.H, 16)
        \\    _ = s
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "must be >= 32");
}

test "intent R-4: extractPrevOutputScript prefixLen = 32 is allowed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    H runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) Bind() {
        \\    s := runar.ExtractPrevOutputScript(0, c.H, 32)
        \\    _ = s
        \\}
    ;

    _ = try mustLowerGoSource(allocator, source);
}

test "intent R-4: extractPrevOutputScript prefixLen > 4 MiB errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    H runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) Bind() {
        \\    s := runar.ExtractPrevOutputScript(0, c.H, 4194305)
        \\    _ = s
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "must be <= MAX_SCRIPT_BYTES");
}

test "intent R-4: extractPrevOutputScript prefixLen = 4 MiB is allowed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    H runar.ByteString `runar:"readonly"`
        \\}
        \\
        \\func (c *Cov) Bind() {
        \\    s := runar.ExtractPrevOutputScript(0, c.H, 4194304)
        \\    _ = s
        \\}
    ;

    _ = try mustLowerGoSource(allocator, source);
}
