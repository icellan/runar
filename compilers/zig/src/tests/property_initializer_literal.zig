//! Audit C3 — property initializers are restricted to literal values.
//!
//! `ts`, `go` and `java` enforced this; `rust`, `zig`, `python` and `ruby` did
//! not — they compiled e.g. `p: bigint = 1n + 2n;` and emitted a deployable
//! locking script for a program the language does not define.
//!
//! Mirrors packages/runar-compiler/src/__tests__/property-initializer-literal.test.ts

const std = @import("std");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const ir_json = @import("../ir/json.zig");

/// The cross-tier diagnostic substring.
const NON_LITERAL_INIT = "initializer must be a literal value";

fn hasError(a: std.mem.Allocator, src: []const u8, needle: []const u8) !bool {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();
    const parsed = parse_ts.parseTs(w, src, "X.runar.ts");
    for (parsed.errors) |e| {
        if (std.mem.indexOf(u8, e, needle) != null) return true;
    }
    if (parsed.contract == null) return false;
    const res = try validate.validate(w, parsed.contract.?);
    for (res.errors) |d| {
        if (std.mem.indexOf(u8, d.message, needle) != null) return true;
    }
    return false;
}

fn errorCount(a: std.mem.Allocator, src: []const u8) !usize {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();
    const parsed = parse_ts.parseTs(w, src, "X.runar.ts");
    if (parsed.errors.len > 0) return parsed.errors.len;
    if (parsed.contract == null) return 0;
    const res = try validate.validate(w, parsed.contract.?);
    return res.errors.len;
}

test "initializer-literal: arithmetic initializer is rejected" {
    const a = std.testing.allocator;
    const src =
        \\class Bad extends StatefulSmartContract {
        \\  count: bigint = 1n + 2n;
        \\  readonly owner: Addr;
        \\  constructor(owner: Addr) { super(owner); this.owner = owner; }
        \\  public bump() {
        \\    this.count = this.count + 1n;
        \\  }
        \\}
    ;
    try std.testing.expect(try hasError(a, src, NON_LITERAL_INIT));
}

test "initializer-literal: call-expression initializer is rejected" {
    const a = std.testing.allocator;
    const src =
        \\class Bad2 extends StatefulSmartContract {
        \\  count: bigint = abs(-3n);
        \\  readonly owner: Addr;
        \\  constructor(owner: Addr) { super(owner); this.owner = owner; }
        \\  public bump() {
        \\    this.count = this.count + 1n;
        \\  }
        \\}
    ;
    try std.testing.expect(try hasError(a, src, NON_LITERAL_INIT));
}

test "initializer-literal: literal initializers are accepted" {
    const a = std.testing.allocator;
    const src =
        \\class Good extends StatefulSmartContract {
        \\  count: bigint = 7n;
        \\  flag: boolean = true;
        \\  tag: ByteString = 'deadbeef';
        \\  offset: bigint = -3n;
        \\  readonly owner: Addr;
        \\  constructor(owner: Addr) { super(owner); this.owner = owner; }
        \\  public bump() {
        \\    this.count = this.count + 1n;
        \\  }
        \\}
    ;
    try std.testing.expectEqual(@as(usize, 0), try errorCount(a, src));
}

// ---------------------------------------------------------------------------
// `toByteString('<hex>')` IS the ByteStringLiteral production — see
// spec/grammar.md section 11:
//
//     ByteStringLiteral = 'toByteString' '(' StringLiteral ')' ;
//
// 0e192af6 folded it in ANF lowering, which covers every EXPRESSION position.
// A property INITIALIZER is not one: the validator runs on the AST, BEFORE ANF
// lowering, and still saw a call node. The `.runar.rs` surface needs exactly
// this spelling in exactly this position — the Rust DSL writes initializers as
// assignments inside `init()` that the parser LIFTS into
// `PropertyNode.initializer`, and a bare `"1976a914"` is a `&str` that cannot
// be assigned to a `ByteString` (`Vec<u8>`).
//
// Both halves are asserted: accepting it in the validator alone yields a
// property that validates and then loses its default, because
// `extractLiteralValue` returns null for a call node.
// ---------------------------------------------------------------------------

const TO_BYTE_STRING_INIT =
    \\class Wrapped extends SmartContract {
    \\  readonly prefix: ByteString = toByteString('1976a914');
    \\  readonly owner: Addr;
    \\  constructor(owner: Addr) { super(owner); this.owner = owner; }
    \\  public unlock(x: ByteString) {
    \\    assert(x === this.prefix);
    \\  }
    \\}
;

const TO_BYTE_STRING_INIT_BARE =
    \\class Wrapped extends SmartContract {
    \\  readonly prefix: ByteString = '1976a914';
    \\  readonly owner: Addr;
    \\  constructor(owner: Addr) { super(owner); this.owner = owner; }
    \\  public unlock(x: ByteString) {
    \\    assert(x === this.prefix);
    \\  }
    \\}
;

test "initializer-literal: toByteString(<literal>) initializer is accepted" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(usize, 0), try errorCount(a, TO_BYTE_STRING_INIT));
}

test "initializer-literal: toByteString(<literal>) initializer unwraps in ANF" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const w = arena.allocator();

    const parsed = parse_ts.parseTs(w, TO_BYTE_STRING_INIT, "X.runar.ts");
    try std.testing.expect(parsed.contract != null);
    const wrapped = try anf_lower.lowerToANF(w, parsed.contract.?);

    const parsed_bare = parse_ts.parseTs(w, TO_BYTE_STRING_INIT_BARE, "X.runar.ts");
    try std.testing.expect(parsed_bare.contract != null);
    const bare = try anf_lower.lowerToANF(w, parsed_bare.contract.?);

    // Half two: a bare value, not a call node and not a dropped default.
    const init_value = wrapped.properties[0].initial_value orelse
        return error.InitialValueWasDropped;
    try std.testing.expectEqualStrings("1976a914", init_value.string);

    // ...and the whole program is indistinguishable from the bare spelling,
    // which is what keeps expected-ir.json from moving.
    const wrapped_json = try ir_json.serializeCanonicalJSON(w, wrapped);
    const bare_json = try ir_json.serializeCanonicalJSON(w, bare);
    try std.testing.expectEqualStrings(bare_json, wrapped_json);
}

test "initializer-literal: toByteString(<non-literal>) initializer is rejected" {
    // Not the ByteStringLiteral production — a real call, and a call is not a
    // literal. Guards the accept from widening into "any toByteString call".
    const a = std.testing.allocator;
    const src =
        \\class Bad3 extends SmartContract {
        \\  readonly prefix: ByteString = toByteString(someIdent);
        \\  readonly owner: Addr;
        \\  constructor(owner: Addr) { super(owner); this.owner = owner; }
        \\  public unlock(x: ByteString) {
        \\    assert(x === this.prefix);
        \\  }
        \\}
    ;
    try std.testing.expect(try hasError(a, src, NON_LITERAL_INIT));
}
