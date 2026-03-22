const std = @import("std");
const types = @import("ir/types.zig");
const parse_zig = @import("passes/parse_zig.zig");
const validate_pass = @import("passes/validate.zig");
const typecheck_pass = @import("passes/typecheck.zig");
const anf_lower = @import("passes/anf_lower.zig");
const constant_fold = @import("passes/constant_fold.zig");
const ec_optimizer = @import("passes/ec_optimizer.zig");
const stack_lower = @import("passes/stack_lower.zig");
const peephole = @import("passes/peephole.zig");
const emit = @import("codegen/emit.zig");

pub const CompileError = error{
    ParseFailed,
    ValidationFailed,
    TypeCheckFailed,
    OutOfMemory,
    ANFLowerFailed,
    StackLowerFailed,
    EmitFailed,
};

pub const CompileResult = struct {
    script_hex: []const u8,
    artifact_json: ?[]const u8,

    pub fn deinit(self: CompileResult, allocator: std.mem.Allocator) void {
        allocator.free(self.script_hex);
        if (self.artifact_json) |json| allocator.free(json);
    }
};

// Compile a .runar.zig source string through the full pipeline,
// returning both the hex script and the JSON artifact.
pub fn compileSource(
    allocator: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
) CompileError!CompileResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const work = arena.allocator();

    // Pass 1: Parse
    const parse_result = parse_zig.parseZig(work, source, file_name);
    if (parse_result.errors.len > 0) return error.ParseFailed;
    const contract = parse_result.contract orelse return error.ParseFailed;

    // Pass 2: Validate (Zig mode — relaxes super() constructor requirement)
    const val_result = validate_pass.validateZig(work, contract) catch return error.ValidationFailed;
    if (val_result.errors.len > 0) return error.ValidationFailed;

    // Pass 3: Typecheck
    const tc_result = typecheck_pass.typeCheck(work, contract) catch return error.TypeCheckFailed;
    if (tc_result.errors.len > 0) return error.TypeCheckFailed;

    // Pass 4: ANF Lower
    var program = anf_lower.lowerToANF(work, contract) catch return error.ANFLowerFailed;

    // Pass 4.25: Constant Fold
    program = constant_fold.foldConstants(work, program) catch return error.ANFLowerFailed;

    // Pass 4.5: EC Optimize
    program = ec_optimizer.optimize(work, program) catch return error.ANFLowerFailed;

    // Pass 5: Stack Lower + Peephole
    const stack_program = stack_lower.lower(work, program) catch return error.StackLowerFailed;
    const optimized_methods = peephole.optimize(work, stack_program.methods) catch return error.StackLowerFailed;
    const optimized_stack_program = types.StackProgram{
        .methods = optimized_methods,
        .contract_name = stack_program.contract_name,
        .properties = stack_program.properties,
        .constructor_params = stack_program.constructor_params,
    };

    // Pass 6: Emit hex script (concatenate all methods)
    var hex_parts: std.ArrayListUnmanaged(u8) = .empty;
    defer hex_parts.deinit(work);
    for (optimized_stack_program.methods, 0..) |method, i| {
        const hex = emit.emitMethodScript(work, method.instructions) catch return error.EmitFailed;
        hex_parts.appendSlice(work, hex) catch return error.OutOfMemory;
        if (i < optimized_stack_program.methods.len - 1) {
            hex_parts.append(work, '\n') catch return error.OutOfMemory;
        }
    }

    // Emit full artifact JSON
    const artifact_json_work = emit.emitArtifact(work, optimized_stack_program, program) catch return error.EmitFailed;

    // Copy results to caller's allocator
    const script_hex = allocator.dupe(u8, hex_parts.items) catch return error.OutOfMemory;
    errdefer allocator.free(script_hex);
    const artifact_json = allocator.dupe(u8, artifact_json_work) catch return error.OutOfMemory;

    return .{
        .script_hex = script_hex,
        .artifact_json = artifact_json,
    };
}

// Compile a .runar.zig source string to hex Bitcoin Script only.
pub fn compileSourceToHex(
    allocator: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
) CompileError![]const u8 {
    const result = try compileSource(allocator, source, file_name);
    if (result.artifact_json) |json| allocator.free(json);
    return result.script_hex;
}

test "compile P2PKH contract to hex" {
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
        \\        runar.assert(runar.hash160(pubKey) == self.pubKeyHash);
        \\        runar.assert(runar.checkSig(sig, pubKey));
        \\    }
        \\};
    ;

    const hex = try compileSourceToHex(std.testing.allocator, source, "P2PKH.runar.zig");
    defer std.testing.allocator.free(hex);

    // Should produce non-empty hex
    try std.testing.expect(hex.len > 0);

    // P2PKH script should contain OP_DUP (76), OP_HASH160 (a9),
    // OP_EQUALVERIFY (88), OP_CHECKSIG (ac) somewhere in the output
    try std.testing.expect(std.mem.indexOf(u8, hex, "76") != null);
    try std.testing.expect(std.mem.indexOf(u8, hex, "a9") != null);
    try std.testing.expect(std.mem.indexOf(u8, hex, "ac") != null);
}

test "compile returns error for invalid contract" {
    const source = "this is not valid zig";
    try std.testing.expectError(
        error.ParseFailed,
        compileSourceToHex(std.testing.allocator, source, "bad.runar.zig"),
    );
}
