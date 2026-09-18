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
        \\    // W2: both calls name index 0 -- any literal index above 0 is refused now.
        \\    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
        \\    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
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
// requireOutputP2PKH(0) + single-output state continuation collision
// ============================================================================

test "intent: requireOutputP2PKH(0) with state mutation is permanently unspendable" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // payBond mutates Count (single-output continuation claims output 0) AND
    // asserts output 0 is a bond P2PKH — output 0 cannot be both codePart and
    // a 34-byte P2PKH.
    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    BondPKH runar.ByteString `runar:"readonly"`
        \\    Bond    runar.Bigint     `runar:"readonly"`
        \\    Count   runar.Bigint
        \\}
        \\
        \\func (c *Cov) PayBond() {
        \\    runar.RequireOutputP2PKH(0, c.BondPKH, c.Bond)
        \\    c.Count = c.Count + 1
        \\}
    ;

    try expectIntrinsicTypeError(allocator, source, "permanently unspendable");
}

test "intent: requireOutputP2PKH(0) terminal method (no mutation) ok" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // No state mutation -> no auto-injected continuation on output 0, so the
    // bond P2PKH at output 0 is valid. Same struct as the mutating variant;
    // only the `c.Count = ...` line is removed.
    const source =
        \\package x
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type Cov struct {
        \\    runar.StatefulSmartContract
        \\    BondPKH runar.ByteString `runar:"readonly"`
        \\    Bond    runar.Bigint     `runar:"readonly"`
        \\    Count   runar.Bigint
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

    try expectIntrinsicTypeError(allocator, source, "must be 0 in v1");
}

// W2: the accepted index is 0, not 1000. Kept as the positive half of the
// bound pair so the refusal above cannot pass by refusing everything.
test "intent R-2: requireOutputP2PKH index 0 is allowed" {
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

// ============================================================================
// N-060 — a `-0` index evades the literal gate and silently DELETES the
// covenant.
//
// The typecheck index gate in typecheck.zig accepts `unary_op{.negate}` over a
// `literal_int` only so that a negative index reports "must be >= 0" instead of
// the misleading "must be an integer literal". `-0` negates to `0`, so it
// passes that bound check — but ANF lowering matches on a BARE `.literal_int`
// and, finding a `.unary_op`, falls through to `load_const ""`: no witness
// param, no hash assertion, NO COVENANT, and no diagnostic. A contract whose
// whole purpose is the covenant compiles to a script that does not carry it.
//
// Mirrors compilers/rust/tests/intent_intrinsics_bounds.rs (R-068).
// ============================================================================

const eps_neg_zero_src =
    \\package x
    \\
    \\import runar "github.com/icellan/runar/packages/runar-go"
    \\
    \\type Cov struct {
    \\    runar.StatefulSmartContract
    \\    H     runar.ByteString
    \\    Count runar.Bigint
    \\}
    \\
    \\func (c *Cov) Bind() {
    \\    s := runar.ExtractPrevOutputScript(-0, c.H)
    \\    runar.Assert(runar.Len(s) > 0)
    \\    c.Count = c.Count + 1
    \\}
;

const rop_neg_zero_src =
    \\package x
    \\
    \\import runar "github.com/icellan/runar/packages/runar-go"
    \\
    \\type Cov struct {
    \\    runar.StatefulSmartContract
    \\    PKH   runar.ByteString
    \\    Amt   runar.Bigint
    \\    Count runar.Bigint
    \\}
    \\
    \\func (c *Cov) Pay() {
    \\    runar.RequireOutputP2PKH(-0, c.PKH, c.Amt)
    \\    c.Count = c.Count + 1
    \\}
;

/// Lower to ANF, returning null when typecheck rejected the source.
fn lowerIfAccepted(allocator: Allocator, source: []const u8) !?[]const ANFMethod {
    const parse_result = parse_go.parseGo(allocator, source, "Test.runar.go");
    if (parse_result.errors.len > 0) return error.UnexpectedParseErrors;
    const contract = parse_result.contract orelse return error.NoContract;
    const tc_result = try typecheck.typeCheck(allocator, contract);
    if (tc_result.errors.len > 0) return null;
    const program = try anf_lower.lowerToANF(allocator, contract);
    return program.methods;
}

fn anyParam(methods: []const ANFMethod, prefix: []const u8) bool {
    for (methods) |m| {
        for (m.params) |p| {
            if (std.mem.startsWith(u8, p.name, prefix)) return true;
        }
    }
    return false;
}

test "intent N-060: extractPrevOutputScript rejects a -0 index" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try expectIntrinsicTypeError(arena.allocator(), eps_neg_zero_src, "must be an integer literal");
}

test "intent N-060: requireOutputP2PKH rejects a -0 index" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try expectIntrinsicTypeError(arena.allocator(), rop_neg_zero_src, "must be an integer literal");
}

// The funds-safety half of the pair: a `-0` index must never reach codegen,
// because when it does the intrinsic lowers to a bare empty-string constant
// and the covenant it was supposed to install is simply absent.
test "intent N-060: a -0 index never silently drops the covenant" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    for ([_][]const u8{ eps_neg_zero_src, rop_neg_zero_src }) |src| {
        const methods = (try lowerIfAccepted(allocator, src)) orelse continue;
        std.debug.print(
            "(-0, ...) compiled with NO diagnostic; covenant params present: _prevOutScript_={} _serialisedOutputs={}\n",
            .{ anyParam(methods, "_prevOutScript_"), anyParam(methods, "_serialisedOutputs") },
        );
        return error.NegativeZeroCovenantDropped;
    }
}

// Controls — the valid forms must keep lowering exactly as before.

test "intent N-060 CONTROL: a literal 0 index still installs the covenant" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const eps = try std.mem.replaceOwned(u8, allocator, eps_neg_zero_src, "ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(0,");
    const eps_methods = (try lowerIfAccepted(allocator, eps)) orelse return error.ValidEpsContractMustLower;
    try std.testing.expect(anyParam(eps_methods, "_prevOutScript_0"));

    // W2: 0 is the only index this intrinsic accepts. The state write also has
    // to go: R-300 refuses `requireOutputP2PKH(0, ...)` in a state-mutating
    // method, because the implicit continuation puts the contract's own
    // codePart at output 0. Index 1 used to dodge that and is no longer legal.
    const rop_idx0 = try std.mem.replaceOwned(u8, allocator, rop_neg_zero_src, "RequireOutputP2PKH(-0,", "RequireOutputP2PKH(0,");
    const rop = try std.mem.replaceOwned(u8, allocator, rop_idx0, "\n    c.Count = c.Count + 1", "");
    const rop_methods = (try lowerIfAccepted(allocator, rop)) orelse return error.ValidRopContractMustLower;
    try std.testing.expect(anyParam(rop_methods, "_serialisedOutputs"));
}

test "intent N-060 CONTROL: a plain negative index still reports the bound message" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const src = try std.mem.replaceOwned(u8, allocator, eps_neg_zero_src, "ExtractPrevOutputScript(-0,", "ExtractPrevOutputScript(-3,");
    try expectIntrinsicTypeError(allocator, src, "must be >= 0");
}
