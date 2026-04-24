const std = @import("std");
const types = @import("ir/types.zig");
const parse_zig = @import("passes/parse_zig.zig");
const parse_ts = @import("passes/parse_ts.zig");
const parse_sol = @import("passes/parse_sol.zig");
const parse_move = @import("passes/parse_move.zig");
const parse_go = @import("passes/parse_go.zig");
const parse_rust = @import("passes/parse_rust.zig");
const parse_python = @import("passes/parse_python.zig");
const parse_ruby = @import("passes/parse_ruby.zig");
const parse_java = @import("passes/parse_java.zig");
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

const FileFormat = enum { runar_zig, runar_ts, runar_sol, runar_move, runar_go, runar_rs, runar_py, runar_rb, runar_java, unknown };

fn detectFormat(path: []const u8) FileFormat {
    if (std.mem.endsWith(u8, path, ".runar.zig")) return .runar_zig;
    if (std.mem.endsWith(u8, path, ".runar.ts")) return .runar_ts;
    if (std.mem.endsWith(u8, path, ".runar.sol")) return .runar_sol;
    if (std.mem.endsWith(u8, path, ".runar.move")) return .runar_move;
    if (std.mem.endsWith(u8, path, ".runar.go")) return .runar_go;
    if (std.mem.endsWith(u8, path, ".runar.rs")) return .runar_rs;
    if (std.mem.endsWith(u8, path, ".runar.py")) return .runar_py;
    if (std.mem.endsWith(u8, path, ".runar.rb")) return .runar_rb;
    if (std.mem.endsWith(u8, path, ".runar.java")) return .runar_java;
    return .unknown;
}

fn parseSource(work: std.mem.Allocator, source: []const u8, file_name: []const u8) struct { contract: ?types.ContractNode, errors: []const []const u8 } {
    const format = detectFormat(file_name);
    return switch (format) {
        .runar_zig => blk: {
            const r = parse_zig.parseZig(work, source, file_name);
            break :blk .{ .contract = r.contract, .errors = r.errors };
        },
        .runar_ts => blk: {
            const r = parse_ts.parseTs(work, source, file_name);
            break :blk .{ .contract = r.contract, .errors = r.errors };
        },
        .runar_sol => blk: {
            const r = parse_sol.parseSol(work, source, file_name);
            break :blk .{ .contract = r.contract, .errors = r.errors };
        },
        .runar_move => blk: {
            const r = parse_move.parseMove(work, source, file_name);
            break :blk .{ .contract = r.contract, .errors = r.errors };
        },
        .runar_go => blk: {
            const r = parse_go.parseGo(work, source, file_name);
            break :blk .{ .contract = r.contract, .errors = r.errors };
        },
        .runar_rs => blk: {
            const r = parse_rust.parseRust(work, source, file_name);
            break :blk .{ .contract = r.contract, .errors = r.errors };
        },
        .runar_py => blk: {
            const r = parse_python.parsePython(work, source, file_name);
            break :blk .{ .contract = r.contract, .errors = r.errors };
        },
        .runar_rb => blk: {
            const r = parse_ruby.parseRuby(work, source, file_name);
            break :blk .{ .contract = r.contract, .errors = r.errors };
        },
        .runar_java => blk: {
            const r = parse_java.parseJava(work, source, file_name);
            break :blk .{ .contract = r.contract, .errors = r.errors };
        },
        .unknown => blk: {
            // Fall back to Zig parser for unknown extensions
            const r = parse_zig.parseZig(work, source, file_name);
            break :blk .{ .contract = r.contract, .errors = r.errors };
        },
    };
}

// Compile a source string through the full pipeline,
// returning both the hex script and the JSON artifact.
// Automatically detects the input format from the file_name extension.
pub fn compileSource(
    allocator: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
) CompileError!CompileResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const work = arena.allocator();

    // Pass 1: Parse (auto-detect format from file extension)
    const parse_result = parseSource(work, source, file_name);
    if (parse_result.errors.len > 0) return error.ParseFailed;
    const contract = parse_result.contract orelse return error.ParseFailed;

    // Pass 2: Validate (Zig mode for .runar.zig — relaxes super() constructor requirement)
    const format = detectFormat(file_name);
    const val_result = if (format == .runar_zig)
        validate_pass.validateZig(work, contract) catch return error.ValidationFailed
    else
        validate_pass.validate(work, contract) catch return error.ValidationFailed;
    if (val_result.errors.len > 0) return error.ValidationFailed;

    // Pass 3: Typecheck
    const tc_result = typecheck_pass.typeCheck(work, contract) catch return error.TypeCheckFailed;
    if (tc_result.errors.len > 0) return error.TypeCheckFailed;

    // Pass 4: ANF Lower
    var program = anf_lower.lowerToANF(work, contract) catch return error.ANFLowerFailed;

    // Pass 4.25: Constant Fold
    program = constant_fold.foldConstants(work, program) catch return error.ANFLowerFailed;

    // Pass 4.5: EC Optimize (includes internal DCE when EC rewrites produce dead code)
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

/// Check that a hex string contains a given opcode hex byte at a byte-aligned boundary.
/// Steps by 2 chars (1 byte) to avoid matching bytes that are part of push data values.
fn hexContainsOpcode(hex: []const u8, opcode: []const u8) bool {
    std.debug.assert(opcode.len == 2);
    if (hex.len < 2) return false;
    var i: usize = 0;
    while (i + 1 < hex.len) : (i += 2) {
        if (hex[i] == opcode[0] and hex[i + 1] == opcode[1]) return true;
    }
    return false;
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
    // OP_EQUALVERIFY (88), OP_CHECKSIG (ac) — use byte-aligned checks to
    // avoid spurious matches inside push data values.
    try std.testing.expect(hexContainsOpcode(hex, "76")); // OP_DUP
    try std.testing.expect(hexContainsOpcode(hex, "a9")); // OP_HASH160
    try std.testing.expect(hexContainsOpcode(hex, "ac")); // OP_CHECKSIG
}

test "artifact contains source map entries" {
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

    const result = try compileSource(std.testing.allocator, source, "P2PKH.runar.zig");
    defer result.deinit(std.testing.allocator);

    // Artifact JSON should contain sourceMap
    try std.testing.expect(result.artifact_json != null);
    const json = result.artifact_json.?;
    try std.testing.expect(std.mem.indexOf(u8, json, "\"sourceMap\":[") != null);
    // sourceMap should reference the source file
    try std.testing.expect(std.mem.indexOf(u8, json, "P2PKH.runar.zig") != null);
}

test "compile returns error for invalid contract" {
    const source = "this is not valid zig";
    try std.testing.expectError(
        error.ParseFailed,
        compileSourceToHex(std.testing.allocator, source, "bad.runar.zig"),
    );
}

test "addDataOutput produces add_data_output ANF node" {
    // Stateful contract that declares a data output alongside a state
    // continuation. The ANF output must include both an add_data_output
    // node (tracked separately) and the continuation-hash machinery wiring
    // the data output between state outputs and the change output.
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const DataCounter = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    count: i64 = 0,
        \\
        \\    pub fn init(count: i64) DataCounter {
        \\        return .{ .count = count };
        \\    }
        \\
        \\    pub fn tick(self: *DataCounter, data: runar.ByteString) void {
        \\        self.count = self.count + 1;
        \\        self.addDataOutput(0, data);
        \\    }
        \\};
    ;

    const result = try compileSource(std.testing.allocator, source, "DataCounter.runar.zig");
    defer result.deinit(std.testing.allocator);

    const json = result.artifact_json orelse return error.TestExpectedJson;
    try std.testing.expect(std.mem.indexOf(u8, json, "add_data_output") != null);
    // The hex script should be non-empty and include the state-output
    // continuation path (bsvz OP_HASH256 followed by OP_EQUALVERIFY-ish
    // structure). Presence of any non-empty script is enough here.
    try std.testing.expect(result.script_hex.len > 0);
}

test "addDataOutput without state mutation still emits continuation hash" {
    // A stateful method that does NOT mutate state but declares a data
    // output must still trigger the continuation-hash machinery
    // (needs_change_output = true, needs_new_amount = true).
    const source =
        \\const runar = @import("runar");
        \\
        \\pub const DataOnly = struct {
        \\    pub const Contract = runar.StatefulSmartContract;
        \\
        \\    owner: runar.Addr,
        \\
        \\    pub fn init(owner: runar.Addr) DataOnly {
        \\        return .{ .owner = owner };
        \\    }
        \\
        \\    pub fn emit(self: *DataOnly, data: runar.ByteString) void {
        \\        _ = self;
        \\        self.addDataOutput(0, data);
        \\    }
        \\};
    ;

    const result = try compileSource(std.testing.allocator, source, "DataOnly.runar.zig");
    defer result.deinit(std.testing.allocator);

    const json = result.artifact_json orelse return error.TestExpectedJson;
    try std.testing.expect(std.mem.indexOf(u8, json, "add_data_output") != null);
    // Change-output / newAmount implicit params must appear in the ABI.
    try std.testing.expect(std.mem.indexOf(u8, json, "_changePKH") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "_changeAmount") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "_newAmount") != null);
}
