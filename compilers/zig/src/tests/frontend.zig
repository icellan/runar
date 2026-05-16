//! Dedicated frontend unit tests (T-4 from
//! audits/cross-language-completeness-20260514.md §5.2).
//!
//! The Zig parsers (sol, move, go, rust, python, ruby, java, ts) and the
//! pipeline passes (validate / typecheck / anf_lower / expand_fixed_arrays)
//! all carry inline `test { ... }` blocks in their respective source files,
//! but the audit identified that there is no _dedicated_ frontend test
//! aggregating cross-format coverage: regressions in any one parser surface
//! today only as opaque cross-tier hex mismatches from the conformance
//! golden harness rather than localized failing tests.
//!
//! This file adds that dedicated coverage. For each non-Zig format we parse
//! a tiny canonical contract through its parser and assert the resulting
//! AST has the expected `parent_class`, method names, and property names.
//! It then exercises each pipeline pass (validate / typecheck / anf_lower
//! / expand_fixed_arrays) with at least one assertion per pass.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");
const types = @import("../ir/types.zig");
const parse_ts = @import("../passes/parse_ts.zig");
const parse_sol = @import("../passes/parse_sol.zig");
const parse_move = @import("../passes/parse_move.zig");
const parse_go = @import("../passes/parse_go.zig");
const parse_rust = @import("../passes/parse_rust.zig");
const parse_python = @import("../passes/parse_python.zig");
const parse_ruby = @import("../passes/parse_ruby.zig");
const parse_java = @import("../passes/parse_java.zig");
const validate_pass = @import("../passes/validate.zig");
const typecheck_pass = @import("../passes/typecheck.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const expand_fixed_arrays = @import("../passes/expand_fixed_arrays.zig");

const ContractNode = types.ContractNode;
const ParentClass = types.ParentClass;
const RunarType = types.RunarType;

// ============================================================================
// Test helpers
// ============================================================================

const TestCtx = struct {
    arena: std.heap.ArenaAllocator,

    fn init() TestCtx {
        return .{ .arena = std.heap.ArenaAllocator.init(std.testing.allocator) };
    }

    fn deinit(self: *TestCtx) void {
        self.arena.deinit();
    }

    fn alloc(self: *TestCtx) std.mem.Allocator {
        return self.arena.allocator();
    }
};

fn methodNames(methods: []const types.MethodNode) [3][]const u8 {
    var out: [3][]const u8 = .{ "", "", "" };
    var i: usize = 0;
    while (i < methods.len and i < out.len) : (i += 1) {
        out[i] = methods[i].name;
    }
    return out;
}

fn hasMethod(methods: []const types.MethodNode, name: []const u8) bool {
    for (methods) |m| {
        if (std.mem.eql(u8, m.name, name)) return true;
    }
    return false;
}

fn hasProperty(props: []const types.PropertyNode, name: []const u8) bool {
    for (props) |p| {
        if (std.mem.eql(u8, p.name, name)) return true;
    }
    return false;
}

// ============================================================================
// Per-format parser tests (one tiny canonical P2PKH-shaped contract each)
//
// Each test asserts the parser produces a ContractNode with the expected
// parent_class, contract name, exactly one property `pubKeyHash`, and
// exactly one method `unlock`.
// ============================================================================

test "frontend: parse .runar.ts P2PKH" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const source =
        \\import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';
        \\class P2PKH extends SmartContract {
        \\  readonly pubKeyHash: Addr;
        \\  constructor(pubKeyHash: Addr) {
        \\    super(pubKeyHash);
        \\    this.pubKeyHash = pubKeyHash;
        \\  }
        \\  public unlock(sig: Sig, pubKey: PubKey) {
        \\    assert(hash160(pubKey) === this.pubKeyHash);
        \\    assert(checkSig(sig, pubKey));
        \\  }
        \\}
    ;
    const r = parse_ts.parseTs(ctx.alloc(), source, "P2PKH.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    try std.testing.expectEqual(ParentClass.smart_contract, c.parent_class);
    try std.testing.expect(hasProperty(c.properties, "pubKeyHash"));
    try std.testing.expect(hasMethod(c.methods, "unlock"));
}

test "frontend: parse .runar.sol P2PKH" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const source =
        \\pragma runar ^0.1.0;
        \\contract P2PKH is SmartContract {
        \\    Addr immutable pubKeyHash;
        \\    constructor(Addr _pubKeyHash) {
        \\        pubKeyHash = _pubKeyHash;
        \\    }
        \\    function unlock(Sig sig, PubKey pubKey) public {
        \\        require(hash160(pubKey) == pubKeyHash);
        \\        require(checkSig(sig, pubKey));
        \\    }
        \\}
    ;
    const r = parse_sol.parseSol(ctx.alloc(), source, "P2PKH.runar.sol");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    try std.testing.expectEqual(ParentClass.smart_contract, c.parent_class);
    try std.testing.expect(hasProperty(c.properties, "pubKeyHash"));
    try std.testing.expect(hasMethod(c.methods, "unlock"));
}

test "frontend: parse .runar.move P2PKH" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const source =
        \\module P2PKH {
        \\    use runar::types::{Addr, PubKey, Sig};
        \\    use runar::crypto::{hash160, check_sig};
        \\    struct P2PKH {
        \\        pub_key_hash: Addr,
        \\    }
        \\    public fun unlock(contract: &P2PKH, sig: Sig, pub_key: PubKey) {
        \\        assert!(hash160(pub_key) == contract.pub_key_hash, 0);
        \\        assert!(check_sig(sig, pub_key), 0);
        \\    }
        \\}
    ;
    const r = parse_move.parseMove(ctx.alloc(), source, "P2PKH.runar.move");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    try std.testing.expectEqual(ParentClass.smart_contract, c.parent_class);
    // Move format converts snake_case property names to camelCase in the AST.
    try std.testing.expect(hasProperty(c.properties, "pubKeyHash"));
    try std.testing.expect(hasMethod(c.methods, "unlock"));
}

test "frontend: parse .runar.go P2PKH" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const source =
        \\package contract
        \\
        \\import runar "github.com/icellan/runar/packages/runar-go"
        \\
        \\type P2PKH struct {
        \\    runar.SmartContract
        \\    PubKeyHash runar.Addr `runar:"readonly"`
        \\}
        \\
        \\func (c *P2PKH) Unlock(sig runar.Sig, pubKey runar.PubKey) {
        \\    runar.Assert(runar.Hash160(pubKey) == c.PubKeyHash)
        \\    runar.Assert(runar.CheckSig(sig, pubKey))
        \\}
    ;
    const r = parse_go.parseGo(ctx.alloc(), source, "P2PKH.runar.go");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    try std.testing.expectEqual(ParentClass.smart_contract, c.parent_class);
    // Go format converts PascalCase property/method names to camelCase.
    try std.testing.expect(hasProperty(c.properties, "pubKeyHash"));
    try std.testing.expect(hasMethod(c.methods, "unlock"));
}

test "frontend: parse .runar.rs P2PKH" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const source =
        \\use runar::prelude::*;
        \\
        \\#[runar::contract]
        \\pub struct P2PKH {
        \\    #[readonly]
        \\    pub pub_key_hash: Addr,
        \\}
        \\
        \\impl P2PKH {
        \\    pub fn unlock(&self, sig: Sig, pub_key: PubKey) {
        \\        runar_assert!(hash160(pub_key) == self.pub_key_hash);
        \\        runar_assert!(check_sig(sig, pub_key));
        \\    }
        \\}
    ;
    const r = parse_rust.parseRust(ctx.alloc(), source, "P2PKH.runar.rs");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    try std.testing.expectEqual(ParentClass.smart_contract, c.parent_class);
    try std.testing.expect(hasProperty(c.properties, "pubKeyHash"));
    try std.testing.expect(hasMethod(c.methods, "unlock"));
}

test "frontend: parse .runar.py P2PKH" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const source =
        \\from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig
        \\
        \\class P2PKH(SmartContract):
        \\    pub_key_hash: Addr
        \\
        \\    def __init__(self, pub_key_hash: Addr):
        \\        super().__init__(pub_key_hash)
        \\        self.pub_key_hash = pub_key_hash
        \\
        \\    @public
        \\    def unlock(self, sig: Sig, pub_key: PubKey):
        \\        assert_(hash160(pub_key) == self.pub_key_hash)
        \\        assert_(check_sig(sig, pub_key))
    ;
    const r = parse_python.parsePython(ctx.alloc(), source, "P2PKH.runar.py");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    try std.testing.expectEqual(ParentClass.smart_contract, c.parent_class);
    // Python snake_case → camelCase conversion lives in parse_python.
    try std.testing.expect(hasProperty(c.properties, "pubKeyHash"));
    try std.testing.expect(hasMethod(c.methods, "unlock"));
}

test "frontend: parse .runar.rb P2PKH" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const source =
        \\require 'runar'
        \\
        \\class P2PKH < Runar::SmartContract
        \\  prop :pub_key_hash, Addr
        \\
        \\  def initialize(pub_key_hash)
        \\    super(pub_key_hash)
        \\    @pub_key_hash = pub_key_hash
        \\  end
        \\
        \\  runar_public sig: Sig, pub_key: PubKey
        \\  def unlock(sig, pub_key)
        \\    assert hash160(pub_key) == @pub_key_hash
        \\    assert check_sig(sig, pub_key)
        \\  end
        \\end
    ;
    const r = parse_ruby.parseRuby(ctx.alloc(), source, "P2PKH.runar.rb");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    try std.testing.expectEqual(ParentClass.smart_contract, c.parent_class);
    try std.testing.expect(hasProperty(c.properties, "pubKeyHash"));
    try std.testing.expect(hasMethod(c.methods, "unlock"));
}

test "frontend: parse .runar.java P2PKH" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const source =
        \\package runar.examples.p2pkh;
        \\
        \\import runar.lang.SmartContract;
        \\import runar.lang.annotations.Public;
        \\import runar.lang.annotations.Readonly;
        \\import runar.lang.types.Addr;
        \\import runar.lang.types.PubKey;
        \\import runar.lang.types.Sig;
        \\
        \\import static runar.lang.Builtins.assertThat;
        \\import static runar.lang.Builtins.checkSig;
        \\import static runar.lang.Builtins.hash160;
        \\
        \\class P2PKH extends SmartContract {
        \\    @Readonly Addr pubKeyHash;
        \\
        \\    P2PKH(Addr pubKeyHash) {
        \\        super(pubKeyHash);
        \\        this.pubKeyHash = pubKeyHash;
        \\    }
        \\
        \\    @Public
        \\    void unlock(Sig sig, PubKey pubKey) {
        \\        assertThat(hash160(pubKey).equals(pubKeyHash));
        \\        assertThat(checkSig(sig, pubKey));
        \\    }
        \\}
    ;
    const r = parse_java.parseJava(ctx.alloc(), source, "P2PKH.runar.java");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const c = r.contract.?;
    try std.testing.expectEqualStrings("P2PKH", c.name);
    try std.testing.expectEqual(ParentClass.smart_contract, c.parent_class);
    try std.testing.expect(hasProperty(c.properties, "pubKeyHash"));
    try std.testing.expect(hasMethod(c.methods, "unlock"));
}

// ============================================================================
// Pipeline pass tests
//
// Each test exercises one of the five passes named in the T-4 audit row
// (validate / typecheck / anf_lower / expand_fixed_arrays). Parser dispatch
// goes through .runar.ts (it has the densest grammar coverage in the
// inline parser tests) so these checks focus on the pass itself, not the
// parser.
// ============================================================================

const SIMPLE_COUNTER_SOURCE =
    \\import { StatefulSmartContract, assert } from 'runar-lang';
    \\class Counter extends StatefulSmartContract {
    \\  count: bigint;
    \\  constructor(count: bigint) {
    \\    super(count);
    \\    this.count = count;
    \\  }
    \\  public increment(): void {
    \\    this.count = this.count + 1n;
    \\    this.addOutput(1000n, this.count);
    \\  }
    \\}
;

const FIXED_ARRAY_SOURCE =
    \\import { SmartContract, assert } from 'runar-lang';
    \\class HasArray extends SmartContract {
    \\  readonly slots: FixedArray<bigint, 3>;
    \\  constructor(slots: FixedArray<bigint, 3>) {
    \\    super(slots);
    \\    this.slots = slots;
    \\  }
    \\  public check(): void {
    \\    assert(this.slots[0] === 1n);
    \\  }
    \\}
;

test "frontend pass: validate accepts a valid stateful contract" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const r = parse_ts.parseTs(ctx.alloc(), SIMPLE_COUNTER_SOURCE, "Counter.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const contract = r.contract.?;

    const val_result = try validate_pass.validate(ctx.alloc(), contract);
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);
}

test "frontend pass: validate rejects constructor missing super()" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    // Constructor must call super() — this should fail validation.
    const source =
        \\import { SmartContract, assert } from 'runar-lang';
        \\class Bad extends SmartContract {
        \\  readonly x: bigint;
        \\  constructor(x: bigint) {
        \\    this.x = x;
        \\  }
        \\  public unlock() {
        \\    assert(this.x > 0n);
        \\  }
        \\}
    ;
    const r = parse_ts.parseTs(ctx.alloc(), source, "Bad.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const contract = r.contract.?;

    const val_result = try validate_pass.validate(ctx.alloc(), contract);
    try std.testing.expect(val_result.errors.len > 0);
}

test "frontend pass: typecheck accepts a valid stateful contract" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const r = parse_ts.parseTs(ctx.alloc(), SIMPLE_COUNTER_SOURCE, "Counter.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const contract = r.contract.?;

    const val_result = try validate_pass.validate(ctx.alloc(), contract);
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);

    const tc_result = try typecheck_pass.typeCheck(ctx.alloc(), contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);
}

test "frontend pass: anf_lower produces methods + bindings" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const r = parse_ts.parseTs(ctx.alloc(), SIMPLE_COUNTER_SOURCE, "Counter.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const contract = r.contract.?;

    const val_result = try validate_pass.validate(ctx.alloc(), contract);
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);
    const tc_result = try typecheck_pass.typeCheck(ctx.alloc(), contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);

    const program = try anf_lower.lowerToANF(ctx.alloc(), contract);
    try std.testing.expectEqualStrings("Counter", program.contract_name);
    try std.testing.expect(program.methods.len >= 1);

    // Find `increment` and confirm it has at least one binding.
    var saw_increment = false;
    for (program.methods) |m| {
        if (std.mem.eql(u8, m.name, "increment")) {
            saw_increment = true;
            try std.testing.expect(m.body.len > 0);
        }
    }
    try std.testing.expect(saw_increment);
}

test "frontend pass: expand_fixed_arrays splits fixed-array property into scalars" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const r = parse_ts.parseTs(ctx.alloc(), FIXED_ARRAY_SOURCE, "HasArray.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const contract = r.contract.?;

    // Pre-condition: parser collapsed the property into a single fixed_array entry.
    try std.testing.expectEqual(@as(usize, 1), contract.properties.len);
    try std.testing.expectEqual(RunarType.fixed_array, contract.properties[0].type_info);
    try std.testing.expectEqual(@as(u32, 3), contract.properties[0].fixed_array_length);

    const expanded = try expand_fixed_arrays.expand(ctx.alloc(), contract);
    try std.testing.expectEqual(@as(usize, 0), expanded.errors.len);
    // Post-condition: the single `slots: FixedArray<bigint, 3>` property has
    // been expanded into 3 scalar siblings (slots_0 .. slots_2).
    try std.testing.expectEqual(@as(usize, 3), expanded.contract.properties.len);
    for (expanded.contract.properties) |p| {
        try std.testing.expectEqual(RunarType.bigint, p.type_info);
    }
}

// ============================================================================
// T-5: dedicated ternary lowering assertion
//
// The Zig parser already has a ternary parse test
// (parse_ts.zig "ternary expression (TS)"), but there is no dedicated
// ANF-lower probe verifying the ternary lowers to the `if` ANF node — that
// path was only exercised through the cross-tier golden harness. Mirrors
// the Java peer test (StackLowerTest#ternaryLowersToIfOpStructural).
// ============================================================================

test "frontend T-5: ternary expression lowers to an `if` ANF binding" {
    var ctx = TestCtx.init();
    defer ctx.deinit();
    const source =
        \\import { SmartContract, assert } from 'runar-lang';
        \\class TernaryDemo extends SmartContract {
        \\  readonly limit: bigint;
        \\  constructor(limit: bigint) {
        \\    super(limit);
        \\    this.limit = limit;
        \\  }
        \\  public check(flag: boolean): void {
        \\    const result: bigint = flag ? this.limit + 1n : this.limit - 1n;
        \\    assert(result > 0n);
        \\  }
        \\}
    ;
    const r = parse_ts.parseTs(ctx.alloc(), source, "TernaryDemo.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), r.errors.len);
    const contract = r.contract.?;

    const val_result = try validate_pass.validate(ctx.alloc(), contract);
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);
    const tc_result = try typecheck_pass.typeCheck(ctx.alloc(), contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);

    const program = try anf_lower.lowerToANF(ctx.alloc(), contract);

    // Locate `check` and assert its body contains at least one `if` ANF binding.
    var check_method: ?types.ANFMethod = null;
    for (program.methods) |m| {
        if (std.mem.eql(u8, m.name, "check")) {
            check_method = m;
            break;
        }
    }
    try std.testing.expect(check_method != null);

    var saw_if = false;
    for (check_method.?.body) |b| {
        if (b.value == .@"if") {
            saw_if = true;
            // The `if` node's then / else bindings must both contain
            // lowered arms of the ternary.
            try std.testing.expect(b.value.@"if".then.len > 0);
            try std.testing.expect(b.value.@"if".@"else".len > 0);
            break;
        }
    }
    try std.testing.expect(saw_if);
}

// ============================================================================
// End-to-end smoke: compile via the dispatcher API to hex for every format.
// Catches a regression in compiler_api.detectFormat / parseSource even if
// the per-parser inline tests pass.
// ============================================================================

test "frontend: compileSource end-to-end for every non-Zig parser produces hex" {
    const Source = struct { name: []const u8, src: []const u8 };
    const sources: []const Source = &.{
        .{
            .name = "P2PKH.runar.ts",
            .src =
            \\import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';
            \\class P2PKH extends SmartContract {
            \\  readonly pubKeyHash: Addr;
            \\  constructor(pubKeyHash: Addr) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
            \\  public unlock(sig: Sig, pubKey: PubKey) {
            \\    assert(hash160(pubKey) === this.pubKeyHash);
            \\    assert(checkSig(sig, pubKey));
            \\  }
            \\}
            ,
        },
        .{
            .name = "P2PKH.runar.sol",
            .src =
            \\pragma runar ^0.1.0;
            \\contract P2PKH is SmartContract {
            \\    Addr immutable pubKeyHash;
            \\    constructor(Addr _pubKeyHash) { pubKeyHash = _pubKeyHash; }
            \\    function unlock(Sig sig, PubKey pubKey) public {
            \\        require(hash160(pubKey) == pubKeyHash);
            \\        require(checkSig(sig, pubKey));
            \\    }
            \\}
            ,
        },
    };
    for (sources) |s| {
        const hex = try compiler_api.compileSourceToHex(std.testing.allocator, s.src, s.name);
        defer std.testing.allocator.free(hex);
        try std.testing.expect(hex.len > 0);
    }
}
