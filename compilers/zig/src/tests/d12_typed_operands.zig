//! D12 FE-F1 / FE-F4: operator lowering reads the operand family the type
//! checker records on the AST, never a heuristic.
//!
//! The end-to-end shapes (bytes, honest / wrong spends) are covered by
//! `conformance/negatives/d12-typed-operand-lowering.test.ts`. These tests
//! pin what that suite cannot see: `lowerToANF` re-runs the type checker when
//! it meets an untagged operator, so a pass that dropped a tag while
//! rebuilding a node would be silently repaired there. Here the tags are
//! checked directly after `expand_fixed_arrays`.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const typecheck = @import("../passes/typecheck.zig");
const expand_fixed_arrays = @import("../passes/expand_fixed_arrays.zig");
const anf_lower = @import("../passes/anf_lower.zig");

const FIXED_ARRAY_SRC =
    \\import { StatefulSmartContract, assert, ByteString, sha256, Sha256, FixedArray } from 'runar-lang';
    \\class Tags extends StatefulSmartContract {
    \\  ks: FixedArray<ByteString, 2>;
    \\  ns: FixedArray<bigint, 3>;
    \\  constructor(ks: FixedArray<ByteString, 2>, ns: FixedArray<bigint, 3>) { super(ks, ns); this.ks = ks; this.ns = ns; }
    \\  public bump(i: bigint, j: bigint, h: Sha256) {
    \\    const v = this.ks[i];
    \\    assert(sha256(v + this.ks[j]) === h);
    \\    assert(~v !== this.ks[j]);
    \\    this.ns[i]++;
    \\    this.ns[j] = this.ns[j] + 1n;
    \\  }
    \\}
;

test "D12: parsers record no operand family; typecheck tags every typed operator" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = compiler_api.parseSource(a, FIXED_ARRAY_SRC, "Tags.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract.?;
    try std.testing.expect(anf_lower.hasUntypedOperator(contract));

    const tc = try typecheck.typeCheck(a, contract);
    try std.testing.expectEqual(@as(usize, 0), tc.errors.len);
    try std.testing.expect(!anf_lower.hasUntypedOperator(contract));
}

test "D12: expand_fixed_arrays keeps every tag and stamps the nodes it synthesises" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = compiler_api.parseSource(a, FIXED_ARRAY_SRC, "Tags.runar.ts");
    const contract = parsed.contract.?;
    const tc = try typecheck.typeCheck(a, contract);
    try std.testing.expectEqual(@as(usize, 0), tc.errors.len);

    const expanded = try expand_fixed_arrays.expand(a, contract);
    try std.testing.expectEqual(@as(usize, 0), expanded.errors.len);
    // The index dispatch (`i === 0`), the `++` desugar (`+ 1`) and every
    // copied operator carry a family: lowering would not need to re-check.
    try std.testing.expect(!anf_lower.hasUntypedOperator(expanded.contract));
}

test "D12: lowerToANF type-checks an untyped AST itself, and refuses what stays untyped" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const ok_src =
        \\import { SmartContract, assert, ByteString } from 'runar-lang';
        \\class Ok extends SmartContract {
        \\  constructor() { super(); }
        \\  public unlock(c: boolean, a: ByteString, b: ByteString) { const x = c ? a : b; assert(x === b); }
        \\}
    ;
    const ok = compiler_api.parseSource(a, ok_src, "Ok.runar.ts").contract.?;
    const program = try anf_lower.lowerToANF(a, ok);
    var saw_bytes_eq = false;
    for (program.methods) |m| for (m.body) |b| switch (b.value) {
        .bin_op => |op| if (std.mem.eql(u8, op.op, "===")) {
            try std.testing.expectEqualStrings("bytes", op.result_type.?);
            saw_bytes_eq = true;
        },
        else => {},
    };
    try std.testing.expect(saw_bytes_eq);

    // `a[0n]` has no type the checker can resolve: no family, so lowering
    // refuses rather than guessing OP_NUMEQUAL.
    const bad_src =
        \\import { SmartContract, assert, ByteString } from 'runar-lang';
        \\class Bad extends SmartContract {
        \\  constructor() { super(); }
        \\  public unlock(a: ByteString, b: ByteString) { assert(a[0n] === b); }
        \\}
    ;
    const bad = compiler_api.parseSource(a, bad_src, "Bad.runar.ts").contract.?;
    var diag: anf_lower.LowerDiagnostic = .{};
    try std.testing.expectError(error.UntypedOperator, anf_lower.lowerToANFWithDiagnostic(a, bad, &diag));
    try std.testing.expect(std.mem.indexOf(u8, diag.message.?, "carries no operand type from the type checker") != null);
}

test "D12 FE-F4: an undeclared helper's return type is inferred with the full environment" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // The helper is defined AFTER its caller and returns a parameter: the old
    // env-less inference typed it `unknown`, and `===` fell back to numeric.
    const src =
        \\import { SmartContract, assert, ByteString } from 'runar-lang';
        \\class Inf extends SmartContract {
        \\  constructor() { super(); }
        \\  public unlock(a: ByteString, b: ByteString) { assert(this.id(a) === this.id(b)); }
        \\  private id(v: ByteString) { return v; }
        \\}
    ;
    const contract = compiler_api.parseSource(a, src, "Inf.runar.ts").contract.?;
    const tc = try typecheck.typeCheck(a, contract);
    try std.testing.expectEqual(@as(usize, 0), tc.errors.len);
    try std.testing.expect(!anf_lower.hasUntypedOperator(contract));
}

test "D12: a nested FixedArray<FixedArray<ByteString>> element read is typed by its leaf" {
    // `this.g[1n][0n] === x` used to type `unknown` here (the parsers kept no
    // leaf type) and the expansion typed the inner arrays `bigint`, refusing
    // the byte-string initializer. TS compiles it to OP_EQUAL; so does this
    // tier, byte for byte (hex captured from the TS reference CLI).
    const src =
        \\import { SmartContract, assert, ByteString, FixedArray, toByteString } from 'runar-lang';
        \\class Nested extends SmartContract {
        \\  readonly g: FixedArray<FixedArray<ByteString, 2>, 2> = [[toByteString('aa'), toByteString('bb')], [toByteString('cc'), toByteString('dd')]];
        \\  constructor() { super(); }
        \\  public unlock(i: bigint, j: bigint, x: ByteString) { assert(this.g[1n][0n] === x); }
        \\}
    ;
    const hex = try compiler_api.compileSourceToHex(std.testing.allocator, src, "Nested.runar.ts");
    defer std.testing.allocator.free(hex);
    try std.testing.expectEqualStrings("01cc7c877777", hex);
}

fn typeErrors(a: std.mem.Allocator, src: []const u8, file: []const u8) ![]const []const u8 {
    const contract = compiler_api.parseSource(a, src, file).contract.?;
    const tc = try typecheck.typeCheck(a, contract);
    return tc.errors;
}

fn anyContains(errs: []const []const u8, needle: []const u8) bool {
    for (errs) |e| if (std.mem.indexOf(u8, e, needle) != null) return true;
    return false;
}

test "D12 FE-F4: a declared FixedArray return type is kept and enforced (TS: 'bigint[]')" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const errs = try typeErrors(arena.allocator(),
        \\import { SmartContract, assert, FixedArray } from 'runar-lang';
        \\class ArrRet extends SmartContract {
        \\  constructor() { super(); }
        \\  private f(x: bigint): FixedArray<bigint, 2> { return x; }
        \\  public unlock(x: bigint) { this.f(x); assert(x > 0n); }
        \\}
    , "ArrRet.runar.ts");
    try std.testing.expect(anyContains(errs, "Method 'f' returns 'bigint', which is not assignable to its declared return type 'bigint[]'"));
}

test "D12 FE-F4: an undeclared helper whose returns do not unify is refused" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const errs = try typeErrors(arena.allocator(),
        \\import { SmartContract, assert } from 'runar-lang';
        \\class Mixed extends SmartContract {
        \\  constructor() { super(); }
        \\  private h(c: boolean) { if (c) { return 1n; } return true; }
        \\  public unlock(c: boolean) { assert(this.h(c)); }
        \\}
    , "Mixed.runar.ts");
    try std.testing.expect(anyContains(errs, "Method 'h' returns values of incompatible types ('bigint', 'boolean'); declare its return type"));

    // Control: returns in one family unify (bigint), so nothing is refused.
    const ok = try typeErrors(arena.allocator(),
        \\import { SmartContract, assert } from 'runar-lang';
        \\class Same extends SmartContract {
        \\  constructor() { super(); }
        \\  private h(c: boolean) { if (c) { return 1n; } return 2n; }
        \\  public unlock(c: boolean) { assert(this.h(c) > 0n); }
        \\}
    , "Same.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), ok.len);
}
