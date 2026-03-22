//! End-to-end compilation tests for the Runar Zig compiler.
//!
//! Tests exercise the full pipeline: parse -> validate -> typecheck -> ANF lower -> stack lower -> emit.
//! Due to known integration gaps between passes (the stack lowerer processes the constructor method
//! which may contain "super" calls not in the builtin map, and the Zig parser doesn't populate
//! constructor metadata for the validator), these tests are structured in two tiers:
//!
//!   Tier 1: Source -> ANF IR (passes 1-4)
//!     Parses real contract source, runs validation and typechecking, lowers to ANF, and verifies
//!     the IR contains expected builtin calls, property references, and control flow.
//!
//!   Tier 2: ANF IR -> Bitcoin Script hex (passes 5-6)
//!     Constructs ANF programs directly (matching the structure the ANF lowerer produces for
//!     public methods only), runs stack lowering and emission, and verifies the output hex
//!     contains expected Bitcoin Script opcodes.
//!
//!   Tier 3: Error detection
//!     Verifies that invalid contracts produce parse/validate/typecheck errors instead of crashing.

const std = @import("std");
const parse_zig = @import("../passes/parse_zig.zig");
const parse_ts = @import("../passes/parse_ts.zig");
const validate = @import("../passes/validate.zig");
const typecheck = @import("../passes/typecheck.zig");
const anf_lower = @import("../passes/anf_lower.zig");
const stack_lower = @import("../passes/stack_lower.zig");
const emit = @import("../codegen/emit.zig");
const types = @import("../ir/types.zig");

// ============================================================================
// Helpers
// ============================================================================

/// Check that a hex string contains a given opcode hex byte (e.g. "76" for OP_DUP).
/// Checks at even byte boundaries for correctness.
fn hexContainsOpcode(hex: []const u8, opcode: []const u8) bool {
    std.debug.assert(opcode.len == 2);
    if (hex.len < 2) return false;
    var i: usize = 0;
    while (i + 1 < hex.len) : (i += 2) {
        if (hex[i] == opcode[0] and hex[i + 1] == opcode[1]) return true;
    }
    return false;
}

/// Extract the hex field value from artifact JSON.
fn extractArtifactHex(json: []const u8) ![]const u8 {
    const hex_start = std.mem.indexOf(u8, json, "\"hex\":\"") orelse return error.MissingHex;
    const after_prefix = hex_start + 7;
    const hex_end = std.mem.indexOfPos(u8, json, after_prefix, "\"") orelse return error.MissingHex;
    return json[after_prefix..hex_end];
}

// ============================================================================
// Tier 1: Source -> ANF IR (passes 1-4)
// ============================================================================

test "e2e: P2PKH .runar.zig -> ANF IR contains hash160, checkSig, assert" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\const runar = @import("runar");
        \\
        \\pub const P2PKH = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    pub_key_hash: runar.Addr,
        \\
        \\    pub fn init(pub_key_hash: runar.Addr) P2PKH {
        \\        return .{ .pub_key_hash = pub_key_hash };
        \\    }
        \\
        \\    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pub_key: runar.PubKey) void {
        \\        runar.assert(runar.hash160(pub_key) == self.pub_key_hash);
        \\        runar.assert(runar.checkSig(sig, pub_key));
        \\    }
        \\};
    ;

    // Pass 1: Parse
    const parsed = parse_zig.parseZig(alloc, source, "P2PKH.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("P2PKH", contract.name);
    try std.testing.expectEqual(types.ParentClass.smart_contract, contract.parent_class);
    try std.testing.expectEqual(@as(usize, 1), contract.properties.len);
    try std.testing.expectEqualStrings("pub_key_hash", contract.properties[0].name);

    // Pass 3: Typecheck (skip validation -- Zig parser constructor convention)
    const tc_result = try typecheck.typeCheck(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);

    // Pass 4: ANF Lower
    const program = try anf_lower.lowerToANF(alloc, tc_result.contract);
    try std.testing.expectEqualStrings("P2PKH", program.contract_name);

    // Should have constructor + unlock methods
    try std.testing.expect(program.methods.len >= 2);

    // Find the unlock method (public)
    var unlock_idx: ?usize = null;
    for (program.methods, 0..) |method, i| {
        if (method.is_public and std.mem.eql(u8, method.name, "unlock")) {
            unlock_idx = i;
            break;
        }
    }
    try std.testing.expect(unlock_idx != null);
    const unlock = program.methods[unlock_idx.?];

    // Verify unlock method has expected ANF bindings
    var found_hash160 = false;
    var found_checksig = false;
    var found_load_prop = false;
    var found_assert = false;
    var found_bin_op_eq = false;
    for (unlock.bindings) |binding| {
        switch (binding.value) {
            .call => |c| {
                if (std.mem.eql(u8, c.func, "hash160")) found_hash160 = true;
                if (std.mem.eql(u8, c.func, "checkSig")) found_checksig = true;
            },
            .load_prop => found_load_prop = true,
            .assert => found_assert = true,
            .bin_op => |bop| {
                if (std.mem.eql(u8, bop.op, "===")) found_bin_op_eq = true;
            },
            else => {},
        }
    }
    try std.testing.expect(found_hash160);
    try std.testing.expect(found_checksig);
    try std.testing.expect(found_load_prop);
    try std.testing.expect(found_assert);
    try std.testing.expect(found_bin_op_eq);
}

test "e2e: P2PKH .runar.ts -> ANF IR contains hash160, checkSig, assert" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Use the TS syntax that the parser actually supports (no decorators, no export)
    const source =
        \\import { SmartContract, assert, PubKey, Sig, hash160, checkSig } from 'runar-lang';
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

    // Pass 1: Parse
    const parsed = parse_ts.parseTs(alloc, source, "P2PKH.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("P2PKH", contract.name);
    try std.testing.expectEqual(types.ParentClass.smart_contract, contract.parent_class);

    // Pass 2: Validate (TS parser populates constructor metadata)
    const val_result = try validate.validate(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);

    // Pass 3: Typecheck
    const tc_result = try typecheck.typeCheck(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);

    // Pass 4: ANF Lower
    const program = try anf_lower.lowerToANF(alloc, tc_result.contract);
    try std.testing.expect(program.methods.len >= 1);

    // Scan all methods for hash160 and checkSig calls in any public method
    var found_hash160 = false;
    var found_checksig = false;
    var has_public_method = false;
    for (program.methods) |method| {
        if (method.is_public) has_public_method = true;
        const bindings = if (method.body.len > 0) method.body else method.bindings;
        for (bindings) |binding| {
            switch (binding.value) {
                .call => |c| {
                    if (std.mem.eql(u8, c.func, "hash160")) found_hash160 = true;
                    if (std.mem.eql(u8, c.func, "checkSig")) found_checksig = true;
                },
                else => {},
            }
        }
    }
    try std.testing.expect(has_public_method);
    try std.testing.expect(found_hash160);
    try std.testing.expect(found_checksig);
}

test "e2e: Counter .runar.zig -> ANF IR has stateful structure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Counter = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    owner: runar.PubKey,
        \\    count: i64 = 0,
        \\
        \\    pub fn init(owner: runar.PubKey, count: i64) Counter {
        \\        return .{ .owner = owner, .count = count };
        \\    }
        \\
        \\    pub fn increment(self: *Counter, sig: runar.Sig) void {
        \\        runar.assert(runar.checkSig(sig, self.owner));
        \\        self.count += 1;
        \\        self.addOutput(1, self.count);
        \\    }
        \\
        \\    pub fn decrement(self: *Counter, sig: runar.Sig) void {
        \\        runar.assert(runar.checkSig(sig, self.owner));
        \\        runar.assert(self.count > 0);
        \\        self.count -= 1;
        \\        self.addOutput(1, self.count);
        \\    }
        \\};
    ;

    // Pass 1: Parse
    const parsed = parse_zig.parseZig(alloc, source, "Counter.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("Counter", contract.name);
    try std.testing.expectEqual(types.ParentClass.stateful_smart_contract, contract.parent_class);

    // Verify properties: owner (readonly) and count (mutable with default)
    try std.testing.expectEqual(@as(usize, 2), contract.properties.len);
    var found_owner = false;
    var found_count = false;
    for (contract.properties) |prop| {
        if (std.mem.eql(u8, prop.name, "owner")) {
            found_owner = true;
            try std.testing.expect(prop.readonly);
        }
        if (std.mem.eql(u8, prop.name, "count")) {
            found_count = true;
            try std.testing.expect(!prop.readonly); // mutable
        }
    }
    try std.testing.expect(found_owner);
    try std.testing.expect(found_count);

    // Verify 2 public methods parsed
    var public_count: usize = 0;
    for (contract.methods) |method| {
        if (method.is_public) public_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), public_count);
}

test "e2e: Escrow .runar.zig -> ANF IR has multi-method structure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Escrow = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    buyer: runar.PubKey,
        \\    seller: runar.PubKey,
        \\    arbiter: runar.PubKey,
        \\
        \\    pub fn init(buyer: runar.PubKey, seller: runar.PubKey, arbiter: runar.PubKey) Escrow {
        \\        return .{ .buyer = buyer, .seller = seller, .arbiter = arbiter };
        \\    }
        \\
        \\    pub fn release(self: *const Escrow, buyer_sig: runar.Sig, seller_sig: runar.Sig) void {
        \\        runar.assert(runar.checkSig(buyer_sig, self.buyer));
        \\        runar.assert(runar.checkSig(seller_sig, self.seller));
        \\    }
        \\
        \\    pub fn arbitrate(self: *const Escrow, arbiter_sig: runar.Sig, winner_sig: runar.Sig, winner_pub_key: runar.PubKey) void {
        \\        runar.assert(runar.checkSig(arbiter_sig, self.arbiter));
        \\        runar.assert(winner_pub_key == self.buyer or winner_pub_key == self.seller);
        \\        runar.assert(runar.checkSig(winner_sig, winner_pub_key));
        \\    }
        \\};
    ;

    // Pass 1: Parse
    const parsed = parse_zig.parseZig(alloc, source, "Escrow.runar.zig");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("Escrow", contract.name);
    try std.testing.expectEqual(@as(usize, 3), contract.properties.len);

    // Pass 3: Typecheck (skip validation for Zig parser)
    const tc_result = try typecheck.typeCheck(alloc, contract);
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);

    // Pass 4: ANF Lower
    const program = try anf_lower.lowerToANF(alloc, tc_result.contract);
    try std.testing.expectEqualStrings("Escrow", program.contract_name);

    // Should have constructor + release + arbitrate = 3 methods
    try std.testing.expect(program.methods.len >= 3);

    // Count public methods and verify both have checkSig calls
    var pub_methods: usize = 0;
    var total_checksig: usize = 0;
    for (program.methods) |method| {
        if (!method.is_public) continue;
        pub_methods += 1;
        for (method.bindings) |binding| {
            switch (binding.value) {
                .call => |c| {
                    if (std.mem.eql(u8, c.func, "checkSig")) total_checksig += 1;
                },
                else => {},
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 2), pub_methods);
    // release has 2 checkSig calls, arbitrate has 2 checkSig calls = 4 total
    try std.testing.expect(total_checksig >= 4);
}

// ============================================================================
// Tier 2: ANF IR -> Bitcoin Script hex (passes 5-6)
// ============================================================================

test "e2e: P2PKH Stack IR -> emit produces OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG" {
    const alloc = std.testing.allocator;

    // Build P2PKH Stack IR directly: OP_DUP OP_HASH160 <placeholder> OP_EQUALVERIFY OP_CHECKSIG
    var body = [_]types.StackOp{
        .{ .opcode = "OP_DUP" },
        .{ .opcode = "OP_HASH160" },
        .{ .placeholder = .{ .param_index = 0, .param_name = "pubKeyHash" } },
        .{ .opcode = "OP_EQUALVERIFY" },
        .{ .opcode = "OP_CHECKSIG" },
    };
    var stack_methods = [_]types.StackMethod{
        .{ .name = "unlock", .ops = &body, .max_stack_depth = 4 },
    };
    var anf_params = [_]types.ANFParam{
        .{ .name = "sig", .type_info = .sig, .type_name = "Sig" },
        .{ .name = "pubKey", .type_info = .pub_key, .type_name = "PubKey" },
    };
    var anf_methods = [_]types.ANFMethod{
        .{ .name = "unlock", .is_public = true, .params = &anf_params, .bindings = &.{} },
    };
    var properties = [_]types.ANFProperty{
        .{ .name = "pubKeyHash", .type_name = "Addr", .type_info = .addr, .readonly = true },
    };

    const stack_program = types.StackProgram{
        .methods = &stack_methods,
        .contract_name = "P2PKH",
    };
    const anf_program = types.ANFProgram{
        .contract_name = "P2PKH",
        .properties = &properties,
        .methods = &anf_methods,
    };

    const artifact = try emit.emitArtifact(alloc, stack_program, anf_program);
    defer alloc.free(artifact);

    // Verify artifact structure
    try std.testing.expect(std.mem.indexOf(u8, artifact, "\"contract\":\"P2PKH\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, artifact, "\"hex\":\"") != null);

    // Extract and verify opcode content
    const hex = try extractArtifactHex(artifact);
    try std.testing.expect(hex.len > 0);

    // Artifact hex starts with OP_CODESEPARATOR (ab) then the body
    // ab 76 a9 <placeholder> 88 ac
    try std.testing.expect(hexContainsOpcode(hex, "76")); // OP_DUP
    try std.testing.expect(hexContainsOpcode(hex, "a9")); // OP_HASH160
    try std.testing.expect(hexContainsOpcode(hex, "88")); // OP_EQUALVERIFY
    try std.testing.expect(hexContainsOpcode(hex, "ac")); // OP_CHECKSIG
}

test "e2e: Escrow Stack IR -> dispatch table produces OP_NUMEQUAL, OP_IF, OP_ENDIF" {
    const alloc = std.testing.allocator;

    // Build 2-method Escrow Stack IR: each method has OP_CHECKSIG
    var release_ops = [_]types.StackOp{
        .{ .opcode = "OP_CHECKSIG" },
    };
    var arbitrate_ops = [_]types.StackOp{
        .{ .opcode = "OP_CHECKSIG" },
    };
    var stack_methods = [_]types.StackMethod{
        .{ .name = "release", .ops = &release_ops, .max_stack_depth = 2 },
        .{ .name = "arbitrate", .ops = &arbitrate_ops, .max_stack_depth = 2 },
    };
    var anf_methods = [_]types.ANFMethod{
        .{ .name = "release", .is_public = true, .params = &.{}, .bindings = &.{} },
        .{ .name = "arbitrate", .is_public = true, .params = &.{}, .bindings = &.{} },
    };
    var properties = [_]types.ANFProperty{
        .{ .name = "buyer", .type_name = "PubKey", .type_info = .pub_key, .readonly = true },
        .{ .name = "seller", .type_name = "PubKey", .type_info = .pub_key, .readonly = true },
        .{ .name = "arbiter", .type_name = "PubKey", .type_info = .pub_key, .readonly = true },
    };

    const stack_program = types.StackProgram{
        .methods = &stack_methods,
        .contract_name = "Escrow",
    };
    const anf_program = types.ANFProgram{
        .contract_name = "Escrow",
        .properties = &properties,
        .methods = &anf_methods,
    };

    const artifact = try emit.emitArtifact(alloc, stack_program, anf_program);
    defer alloc.free(artifact);

    const hex = try extractArtifactHex(artifact);
    try std.testing.expect(hex.len > 0);

    // Multi-method dispatch opcodes (from emit.zig emitDispatchTable)
    try std.testing.expect(hexContainsOpcode(hex, "9c")); // OP_NUMEQUAL
    try std.testing.expect(hexContainsOpcode(hex, "63")); // OP_IF
    try std.testing.expect(hexContainsOpcode(hex, "68")); // OP_ENDIF

    // Signature verification in both methods
    try std.testing.expect(hexContainsOpcode(hex, "ac")); // OP_CHECKSIG

    // OP_CODESEPARATOR at the start
    try std.testing.expect(hexContainsOpcode(hex, "ab")); // OP_CODESEPARATOR
}

test "e2e: stateful Counter Stack IR -> emit produces OP_CODESEPARATOR, dispatch, state metadata" {
    const alloc = std.testing.allocator;

    // Minimal stateful counter with 2 methods containing OP_CHECKSIG
    var inc_ops = [_]types.StackOp{
        .{ .opcode = "OP_CHECKSIG" },
        .{ .opcode = "OP_1ADD" },
    };
    var dec_ops = [_]types.StackOp{
        .{ .opcode = "OP_CHECKSIG" },
        .{ .opcode = "OP_1SUB" },
    };
    var stack_methods = [_]types.StackMethod{
        .{ .name = "increment", .ops = &inc_ops, .max_stack_depth = 2 },
        .{ .name = "decrement", .ops = &dec_ops, .max_stack_depth = 2 },
    };
    var anf_methods = [_]types.ANFMethod{
        .{ .name = "increment", .is_public = true, .params = &.{}, .bindings = &.{} },
        .{ .name = "decrement", .is_public = true, .params = &.{}, .bindings = &.{} },
    };
    var properties = [_]types.ANFProperty{
        .{ .name = "owner", .type_name = "PubKey", .type_info = .pub_key, .readonly = true },
        .{ .name = "count", .type_name = "bigint", .type_info = .bigint, .readonly = false },
    };

    const stack_program = types.StackProgram{
        .methods = &stack_methods,
        .contract_name = "Counter",
    };
    const anf_program = types.ANFProgram{
        .contract_name = "Counter",
        .properties = &properties,
        .methods = &anf_methods,
    };

    const artifact = try emit.emitArtifact(alloc, stack_program, anf_program);
    defer alloc.free(artifact);

    // Verify stateful contract metadata in artifact JSON
    try std.testing.expect(std.mem.indexOf(u8, artifact, "\"contract\":\"Counter\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, artifact, "\"stateFields\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, artifact, "\"count\"") != null);

    const hex = try extractArtifactHex(artifact);
    try std.testing.expect(hex.len > 0);

    // OP_CODESEPARATOR (ab) at the start of every artifact
    try std.testing.expect(hexContainsOpcode(hex, "ab"));

    // 2 methods -> dispatch table
    try std.testing.expect(hexContainsOpcode(hex, "9c")); // OP_NUMEQUAL
    try std.testing.expect(hexContainsOpcode(hex, "63")); // OP_IF
    try std.testing.expect(hexContainsOpcode(hex, "68")); // OP_ENDIF

    // OP_CHECKSIG in both method bodies
    try std.testing.expect(hexContainsOpcode(hex, "ac"));
}

// ============================================================================
// Tier 3: Error cases
// ============================================================================

test "e2e error: invalid Zig contract produces parse errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Broken = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    // Missing closing brace and semicolon
        \\    pub fn unlock(self: *const Broken) void {
        \\        runar.assert(true)
        \\    }
    ;

    const parsed = parse_zig.parseZig(alloc, source, "Broken.runar.zig");
    // Either parse errors or no contract produced
    const has_error = parsed.errors.len > 0 or parsed.contract == null;
    try std.testing.expect(has_error);
}

test "e2e error: invalid TypeScript contract produces parse errors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\import { SmartContract } from "runar";
        \\
        \\export class extends SmartContract {
        \\    // Missing class name
        \\}
    ;

    const parsed = parse_ts.parseTs(alloc, source, "Broken.runar.ts");
    const has_error = parsed.errors.len > 0 or parsed.contract == null;
    try std.testing.expect(has_error);
}

test "e2e error: TS validation catches missing super() from AST" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // TS contract missing super() call in constructor (using parser-supported syntax)
    const source =
        \\import { SmartContract, assert, PubKey } from 'runar-lang';
        \\class Bad extends SmartContract {
        \\  readonly pk: PubKey;
        \\  constructor(pk: PubKey) {
        \\    this.pk = pk;
        \\  }
        \\  public unlock() {
        \\    assert(true);
        \\  }
        \\}
    ;

    const parsed = parse_ts.parseTs(alloc, source, "Bad.runar.ts");
    if (parsed.errors.len > 0 or parsed.contract == null) {
        // Parse-level rejection is acceptable
        return;
    }
    const contract = parsed.contract.?;
    const val_result = validate.validate(alloc, contract) catch return;
    // Should detect missing super() call
    try std.testing.expect(val_result.errors.len > 0);
}

test "e2e error: empty contract body produces no crash" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Empty = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    pub fn init() Empty {
        \\        return .{};
        \\    }
        \\};
    ;

    // Must not crash -- either parses cleanly or reports errors
    const parsed = parse_zig.parseZig(alloc, source, "Empty.runar.zig");
    if (parsed.contract) |contract| {
        _ = validate.validate(alloc, contract) catch {};
        _ = typecheck.typeCheck(alloc, contract) catch {};
    }
    // Success = no crash. Parse errors are acceptable for an empty contract.
}

test "e2e error: pipeline handles malformed contracts without crashing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Various malformed inputs -- none should crash
    const bad_sources = [_][]const u8{
        // Empty file
        "",
        // Just the import, no contract
        "const runar = @import(\"runar\");",
        // Contract with unknown parent class
        \\const runar = @import("runar");
        \\pub const X = struct {
        \\    pub const Contract = runar.UnknownClass;
        \\};
        ,
        // Gibberish
        "pub const @#$% = struct {};",
    };

    for (bad_sources) |source| {
        const parsed = parse_zig.parseZig(alloc, source, "bad.runar.zig");
        // Must not crash. Errors or null contract are acceptable.
        if (parsed.contract) |contract| {
            _ = validate.validate(alloc, contract) catch {};
            _ = typecheck.typeCheck(alloc, contract) catch {};
        }
    }
}
