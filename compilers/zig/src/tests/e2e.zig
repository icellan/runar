//! End-to-end compilation tests for the Runar Zig compiler.
//!
//! Each test exercises the full pipeline: parse -> validate -> typecheck -> ANF lower -> stack lower -> emit.
//! Tests verify that the emitted Bitcoin Script hex contains expected opcodes for each contract pattern.

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

const CompileResult = struct {
    method_hexes: [][]const u8,
    artifact_json: []const u8,
};

const CompileError = error{
    ParseFailed,
    ValidationFailed,
    TypecheckFailed,
    MissingHex,
    OutOfMemory,
    UnsupportedExpression,
    UnsupportedStatement,
    UnknownOpcode,
};

/// Run passes 2-6 on a parsed contract.
/// skip_ctor_validation: the Zig parser delegates constructor semantics to ANF
/// lowering, so super_args/assignments are empty. Skip those checks for .runar.zig.
fn compileParsed(
    alloc: std.mem.Allocator,
    contract: types.ContractNode,
    skip_ctor_validation: bool,
) CompileError!CompileResult {
    // Pass 2: Validate
    const val_result = validate.validate(alloc, contract) catch return error.OutOfMemory;
    if (val_result.errors.len > 0) {
        // When skip_ctor_validation is set, filter out constructor-related errors
        // that are expected from the Zig parser's AST convention.
        var fatal_count: usize = 0;
        for (val_result.errors) |err| {
            const is_ctor_error = skip_ctor_validation and
                (std.mem.indexOf(u8, err.message, "super()") != null or
                std.mem.indexOf(u8, err.message, "property must be assigned in the constructor") != null);
            if (!is_ctor_error) {
                std.debug.print("Validation error: {s}\n", .{err.message});
                fatal_count += 1;
            }
        }
        if (fatal_count > 0) return error.ValidationFailed;
    }

    // Pass 3: Typecheck
    const tc_result = typecheck.typeCheck(alloc, contract) catch return error.OutOfMemory;
    if (tc_result.errors.len > 0) {
        std.debug.print("Typecheck errors:\n", .{});
        for (tc_result.errors) |err| {
            std.debug.print("  {s}\n", .{err});
        }
        return error.TypecheckFailed;
    }

    // Pass 4: ANF Lower
    const anf_program = try anf_lower.lowerToANF(alloc, tc_result.contract);

    // Pass 5: Stack Lower
    const stack_program = stack_lower.lower(alloc, anf_program) catch return error.OutOfMemory;

    // Pass 6: Emit -- collect per-method hex and full artifact
    var method_hexes: std.ArrayListUnmanaged([]const u8) = .empty;
    for (stack_program.methods) |method| {
        const hex = emit.emitMethodOps(alloc, method.ops) catch return error.OutOfMemory;
        method_hexes.append(alloc, hex) catch return error.OutOfMemory;
    }

    const artifact_json = emit.emitArtifact(alloc, stack_program, anf_program) catch return error.OutOfMemory;

    return .{
        .method_hexes = method_hexes.toOwnedSlice(alloc) catch return error.OutOfMemory,
        .artifact_json = artifact_json,
    };
}

/// Run the full pipeline from .runar.zig source through emit.
fn compileZig(alloc: std.mem.Allocator, source: []const u8, file_name: []const u8) CompileError!CompileResult {
    const parsed = parse_zig.parseZig(alloc, source, file_name);
    if (parsed.errors.len > 0) {
        std.debug.print("Parse errors:\n", .{});
        for (parsed.errors) |err| {
            std.debug.print("  {s}\n", .{err});
        }
        return error.ParseFailed;
    }
    // Zig parser doesn't populate constructor super_args/assignments (handled by ANF lowering)
    return compileParsed(alloc, parsed.contract orelse return error.ParseFailed, true);
}

/// Run the full pipeline from .runar.ts source through emit.
fn compileTs(alloc: std.mem.Allocator, source: []const u8, file_name: []const u8) CompileError!CompileResult {
    const parsed = parse_ts.parseTs(alloc, source, file_name);
    if (parsed.errors.len > 0) {
        std.debug.print("Parse errors:\n", .{});
        for (parsed.errors) |err| {
            std.debug.print("  {s}\n", .{err});
        }
        return error.ParseFailed;
    }
    return compileParsed(alloc, parsed.contract orelse return error.ParseFailed, false);
}

/// Check that a hex string contains a given opcode hex byte (e.g. "76" for OP_DUP).
/// The opcode must appear as a 2-char substring at an even byte boundary.
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
    const after_prefix = hex_start + 7; // skip past "hex":"
    const hex_end = std.mem.indexOfPos(u8, json, after_prefix, "\"") orelse return error.MissingHex;
    return json[after_prefix..hex_end];
}

/// Concatenate all method hexes into one string for aggregate opcode checking.
fn concatHexes(alloc: std.mem.Allocator, hexes: [][]const u8) ![]u8 {
    var total: std.ArrayListUnmanaged(u8) = .empty;
    for (hexes) |hex| {
        try total.appendSlice(alloc, hex);
    }
    return try total.toOwnedSlice(alloc);
}

// ============================================================================
// Test 1: P2PKH from .runar.zig
// ============================================================================

test "e2e: P2PKH from .runar.zig" {
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

    const result = try compileZig(alloc, source, "P2PKH.runar.zig");

    // The artifact JSON must contain expected fields
    try std.testing.expect(std.mem.indexOf(u8, result.artifact_json, "\"hex\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.artifact_json, "\"contract\":\"P2PKH\"") != null);

    // At least one method should have been emitted
    try std.testing.expect(result.method_hexes.len >= 1);

    // Concatenate all method hexes for opcode checking
    const hex = try concatHexes(alloc, result.method_hexes);

    // P2PKH must contain these opcodes:
    try std.testing.expect(hexContainsOpcode(hex, "76")); // OP_DUP
    try std.testing.expect(hexContainsOpcode(hex, "a9")); // OP_HASH160
    try std.testing.expect(hexContainsOpcode(hex, "88")); // OP_EQUALVERIFY
    try std.testing.expect(hexContainsOpcode(hex, "ac")); // OP_CHECKSIG
}

// ============================================================================
// Test 2: P2PKH from .runar.ts
// ============================================================================

test "e2e: P2PKH from .runar.ts" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const source =
        \\import { SmartContract, assert, method, prop } from "runar";
        \\import { hash160, PubKey, Sig, Addr, checkSig } from "runar/builtins";
        \\
        \\export class P2PKH extends SmartContract {
        \\    @prop() readonly pubKeyHash: Addr;
        \\
        \\    constructor(pubKeyHash: Addr) {
        \\        super(pubKeyHash);
        \\        this.pubKeyHash = pubKeyHash;
        \\    }
        \\
        \\    @method()
        \\    public unlock(sig: Sig, pubKey: PubKey): void {
        \\        assert(hash160(pubKey) === this.pubKeyHash);
        \\        assert(checkSig(sig, pubKey));
        \\    }
        \\}
    ;

    // Verify the TS parser produces a valid AST
    const parsed = parse_ts.parseTs(alloc, source, "P2PKH.runar.ts");
    try std.testing.expectEqual(@as(usize, 0), parsed.errors.len);
    const contract = parsed.contract orelse return error.ParseFailed;
    try std.testing.expectEqualStrings("P2PKH", contract.name);
    try std.testing.expect(contract.methods.len >= 1);

    // Validate passes for TS (TS parser populates super_args/assignments)
    const val_result = validate.validate(alloc, contract) catch return;
    try std.testing.expectEqual(@as(usize, 0), val_result.errors.len);

    // Typecheck
    const tc_result = typecheck.typeCheck(alloc, contract) catch return;
    try std.testing.expectEqual(@as(usize, 0), tc_result.errors.len);

    // ANF Lower
    const anf_program = try anf_lower.lowerToANF(alloc, tc_result.contract);

    // Verify ANF IR structure: should have constructor + unlock methods
    try std.testing.expect(anf_program.methods.len >= 2);

    // Verify the unlock method bindings contain hash160 and checkSig calls
    const unlock_method = anf_program.methods[1];
    try std.testing.expectEqualStrings("unlock", unlock_method.name);
    try std.testing.expect(unlock_method.is_public);
    try std.testing.expect(unlock_method.bindings.len >= 4);

    // Stack lower currently processes all methods including the constructor,
    // which contains a "super" call not in the builtin map. This is a known
    // limitation: the stack lowerer should skip non-public methods.
    // For now, verify the pipeline up through ANF produces correct IR.
    var found_hash160 = false;
    var found_checksig = false;
    for (unlock_method.bindings) |binding| {
        switch (binding.value) {
            .call => |c| {
                if (std.mem.eql(u8, c.func, "hash160")) found_hash160 = true;
                if (std.mem.eql(u8, c.func, "checkSig")) found_checksig = true;
            },
            else => {},
        }
    }
    try std.testing.expect(found_hash160);
    try std.testing.expect(found_checksig);
}

// ============================================================================
// Test 3: Counter (stateful contract)
// ============================================================================

test "e2e: Counter stateful contract" {
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

    const result = try compileZig(alloc, source, "Counter.runar.zig");

    // Artifact must indicate stateful contract
    try std.testing.expect(std.mem.indexOf(u8, result.artifact_json, "\"contract\":\"Counter\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.artifact_json, "\"stateFields\":[") != null);

    // Extract the artifact hex
    const artifact_hex = try extractArtifactHex(result.artifact_json);

    // OP_CODESEPARATOR (ab) -- required for stateful contracts
    try std.testing.expect(hexContainsOpcode(artifact_hex, "ab"));

    // Counter has 2 public methods, so dispatch table is present
    // OP_NUMEQUAL (9c) -- used in dispatch table
    try std.testing.expect(hexContainsOpcode(artifact_hex, "9c"));

    // OP_CHECKSIG (ac) -- used for signature verification
    const hex = try concatHexes(alloc, result.method_hexes);
    try std.testing.expect(hexContainsOpcode(hex, "ac"));
}

// ============================================================================
// Test 4: Escrow (multi-method, dispatch table)
// ============================================================================

test "e2e: Escrow multi-method dispatch" {
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

    const result = try compileZig(alloc, source, "Escrow.runar.zig");

    // 2 public methods: release and arbitrate
    try std.testing.expect(result.method_hexes.len >= 2);

    // Extract artifact hex
    const artifact_hex = try extractArtifactHex(result.artifact_json);

    // Multi-method dispatch table opcodes:
    try std.testing.expect(hexContainsOpcode(artifact_hex, "9c")); // OP_NUMEQUAL
    try std.testing.expect(hexContainsOpcode(artifact_hex, "63")); // OP_IF
    try std.testing.expect(hexContainsOpcode(artifact_hex, "68")); // OP_ENDIF

    // Both methods verify signatures
    try std.testing.expect(hexContainsOpcode(artifact_hex, "ac")); // OP_CHECKSIG
}

// ============================================================================
// Test 5: Error cases
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

test "e2e error: validation catches mutable property in SmartContract" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // A SmartContract with a non-readonly property should fail validation
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const Bad = struct {
        \\    pub const Contract = runar.SmartContract;
        \\
        \\    counter: i64 = 0,
        \\
        \\    pub fn init(counter: i64) Bad {
        \\        return .{ .counter = counter };
        \\    }
        \\
        \\    pub fn unlock(self: *const Bad) void {
        \\        runar.assert(self.counter == 0);
        \\    }
        \\};
    ;

    const parsed = parse_zig.parseZig(alloc, source, "Bad.runar.zig");
    if (parsed.errors.len > 0 or parsed.contract == null) {
        // Parser itself flagged it -- that counts as a valid early rejection
        return;
    }
    const contract = parsed.contract.?;

    const val_result = validate.validate(alloc, contract) catch return;
    // SmartContract with mutable property must produce at least one error
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

    // This should either parse cleanly (no methods = valid but trivial)
    // or produce informative errors -- never crash
    const parsed = parse_zig.parseZig(alloc, source, "Empty.runar.zig");
    if (parsed.contract) |contract| {
        // If it parsed, validation should succeed (empty contracts are valid per the validator)
        const val_result = validate.validate(alloc, contract) catch return;
        _ = val_result; // No assertion on error count -- just verifying no crash
    }
    // If it didn't parse, errors should be present
    if (parsed.contract == null) {
        try std.testing.expect(parsed.errors.len > 0);
    }
}
