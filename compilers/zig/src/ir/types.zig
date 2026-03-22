//! Runar IR type definitions — the data structures shared between all compilation passes.
//! These mirror the TypeScript types from runar-compiler/src/ir/ exactly.
//!
//! Layer 1: AST (Pass 1 output) — runar-ast.ts
//! Layer 2: ANF IR (Pass 4 output, conformance boundary) — anf-ir.ts
//! Layer 3: Stack IR (Pass 5 output) — stack-ir.ts
//! Layer 4: Artifact (Pass 6 output) — artifact.ts
//! Layer 5: Support types (diagnostics, source locations)

const std = @import("std");

// ============================================================================
// Opcode — canonical definition lives in codegen/opcodes.zig, re-exported here
// ============================================================================

pub const Opcode = @import("../codegen/opcodes.zig").Opcode;
pub const OP_FALSE = Opcode.op_0;
pub const OP_TRUE = Opcode.op_1;

// ============================================================================
// Layer 5: Support Types
// ============================================================================

pub const SourceLocation = struct {
    file: []const u8,
    line: u32,
    column: u32,
};

pub const DiagnosticSeverity = enum { @"error", warning, info };

pub const CompilerDiagnostic = struct {
    message: []const u8,
    location: ?SourceLocation = null,
    severity: DiagnosticSeverity = .@"error",
};

// ============================================================================
// Layer 1: AST Types (output of Pass 1: Parse) — maps to runar-ast.ts
// ============================================================================

pub const RunarType = enum {
    bigint, boolean, byte_string, pub_key, sig, addr, sha256, ripemd160,
    sig_hash_type, sig_hash_preimage, rabin_sig, rabin_pub_key, point,
    op_code_type, void, unknown,
};

pub const PrimitiveTypeName = enum {
    bigint, boolean, byte_string, pub_key, sig, sha256, ripemd160, addr,
    sig_hash_preimage, rabin_sig, rabin_pub_key, point, void,

    pub fn toTsString(self: PrimitiveTypeName) []const u8 {
        return switch (self) {
            .bigint => "bigint", .boolean => "boolean", .byte_string => "ByteString",
            .pub_key => "PubKey", .sig => "Sig", .sha256 => "Sha256",
            .ripemd160 => "Ripemd160", .addr => "Addr",
            .sig_hash_preimage => "SigHashPreimage", .rabin_sig => "RabinSig",
            .rabin_pub_key => "RabinPubKey", .point => "Point", .void => "void",
        };
    }

    pub fn fromTsString(s: []const u8) ?PrimitiveTypeName {
        const map = std.StaticStringMap(PrimitiveTypeName).initComptime(.{
            .{ "bigint", .bigint }, .{ "boolean", .boolean }, .{ "ByteString", .byte_string },
            .{ "PubKey", .pub_key }, .{ "Sig", .sig }, .{ "Sha256", .sha256 },
            .{ "Ripemd160", .ripemd160 }, .{ "Addr", .addr },
            .{ "SigHashPreimage", .sig_hash_preimage }, .{ "RabinSig", .rabin_sig },
            .{ "RabinPubKey", .rabin_pub_key }, .{ "Point", .point }, .{ "void", .void },
        });
        return map.get(s);
    }
};

pub const TypeNode = union(enum) {
    primitive_type: PrimitiveTypeName,
    fixed_array_type: FixedArrayType,
    custom_type: []const u8,
};

pub const FixedArrayType = struct { element: *const TypeNode, length: u32 };

/// Convert a TypeNode to a RunarType. Custom and fixed-array types become .unknown.
pub fn typeNodeToRunarType(tn: TypeNode) RunarType {
    return switch (tn) {
        .primitive_type => |ptn| switch (ptn) {
            .bigint => .bigint,
            .boolean => .boolean,
            .byte_string => .byte_string,
            .pub_key => .pub_key,
            .sig => .sig,
            .sha256 => .sha256,
            .ripemd160 => .ripemd160,
            .addr => .addr,
            .sig_hash_preimage => .sig_hash_preimage,
            .rabin_sig => .rabin_sig,
            .rabin_pub_key => .rabin_pub_key,
            .point => .point,
            .void => .void,
        },
        .fixed_array_type => .unknown,
        .custom_type => .unknown,
    };
}

pub const ParentClass = enum {
    smart_contract, stateful_smart_contract,

    pub fn toTsString(self: ParentClass) []const u8 {
        return switch (self) { .smart_contract => "SmartContract", .stateful_smart_contract => "StatefulSmartContract" };
    }
    pub fn fromTsString(s: []const u8) ?ParentClass {
        if (std.mem.eql(u8, s, "SmartContract")) return .smart_contract;
        if (std.mem.eql(u8, s, "StatefulSmartContract")) return .stateful_smart_contract;
        return null;
    }
};

pub const ContractNode = struct { name: []const u8, parent_class: ParentClass, properties: []PropertyNode, constructor: ConstructorNode, methods: []MethodNode };
pub const PropertyNode = struct { name: []const u8, type_info: RunarType, readonly: bool, initializer: ?Expression = null };
pub const ConstructorNode = struct { params: []ParamNode, super_args: []Expression, assignments: []AssignmentNode };
pub const MethodNode = struct { name: []const u8, is_public: bool, params: []ParamNode, body: []Statement };
pub const ParamNode = struct { name: []const u8, type_info: RunarType = .unknown, type_name: []const u8 = "" };
pub const ANFParam = ParamNode;
pub const AssignmentNode = struct { target: []const u8, value: Expression };

pub const Statement = union(enum) { const_decl: ConstDecl, let_decl: LetDecl, assign: Assign, if_stmt: IfStmt, for_stmt: ForStmt, expr_stmt: Expression, assert_stmt: AssertStmt, return_stmt: ?Expression };
pub const ConstDecl = struct { name: []const u8, type_info: ?RunarType = null, value: Expression };
pub const LetDecl = struct { name: []const u8, type_info: ?RunarType = null, value: ?Expression = null };
pub const Assign = struct { target: []const u8, value: Expression };
pub const IfStmt = struct { condition: Expression, then_body: []Statement, else_body: ?[]Statement = null };
pub const ForStmt = struct { var_name: []const u8, init_value: i64, bound: i64, body: []Statement };
pub const AssertStmt = struct { condition: Expression, message: ?[]const u8 = null };

pub const Expression = union(enum) {
    literal_int: i64, literal_bool: bool, literal_bytes: []const u8, identifier: []const u8,
    property_access: PropertyAccess, binary_op: *BinaryOp, unary_op: *UnaryOp,
    call: *CallExpr, method_call: *MethodCall, ternary: *Ternary, index_access: *IndexAccess,
    increment: *IncrementExpr, decrement: *DecrementExpr, array_literal: []const Expression,
};
pub const PropertyAccess = struct { object: []const u8, property: []const u8 };
pub const BinaryOp = struct { op: BinOperator, left: Expression, right: Expression };
pub const UnaryOp = struct { op: UnaryOperator, operand: Expression };
pub const CallExpr = struct { callee: []const u8, args: []Expression };
pub const MethodCall = struct { object: []const u8, method: []const u8, args: []Expression };
pub const Ternary = struct { condition: Expression, then_expr: Expression, else_expr: Expression };
pub const IndexAccess = struct { object: Expression, index: Expression };
pub const IncrementExpr = struct { operand: Expression, prefix: bool };
pub const DecrementExpr = struct { operand: Expression, prefix: bool };

pub const BinOperator = enum {
    add, sub, mul, div, mod, eq, neq, lt, gt, lte, gte,
    and_op, or_op, bitand, bitor, bitxor, lshift, rshift,

    pub fn toTsString(self: BinOperator) []const u8 {
        return switch (self) {
            .add => "+", .sub => "-", .mul => "*", .div => "/", .mod => "%",
            .eq => "===", .neq => "!==", .lt => "<", .lte => "<=", .gt => ">", .gte => ">=",
            .and_op => "&&", .or_op => "||", .bitand => "&", .bitor => "|", .bitxor => "^",
            .lshift => "<<", .rshift => ">>",
        };
    }
    pub fn fromTsString(s: []const u8) ?BinOperator {
        const map = std.StaticStringMap(BinOperator).initComptime(.{
            .{ "+", .add }, .{ "-", .sub }, .{ "*", .mul }, .{ "/", .div }, .{ "%", .mod },
            .{ "===", .eq }, .{ "!==", .neq }, .{ "<", .lt }, .{ "<=", .lte },
            .{ ">", .gt }, .{ ">=", .gte }, .{ "&&", .and_op }, .{ "||", .or_op },
            .{ "&", .bitand }, .{ "|", .bitor }, .{ "^", .bitxor },
            .{ "<<", .lshift }, .{ ">>", .rshift },
        });
        return map.get(s);
    }
};

pub const UnaryOperator = enum {
    negate, not, bitnot,
    pub fn toTsString(self: UnaryOperator) []const u8 {
        return switch (self) { .not => "!", .negate => "-", .bitnot => "~" };
    }
    pub fn fromTsString(s: []const u8) ?UnaryOperator {
        if (std.mem.eql(u8, s, "!")) return .not;
        if (std.mem.eql(u8, s, "-")) return .negate;
        if (std.mem.eql(u8, s, "~")) return .bitnot;
        return null;
    }
};

// ============================================================================
// Layer 2: ANF IR Types (output of Pass 4: ANF Lower) — maps to anf-ir.ts
// ============================================================================

pub const ANFProgram = struct {
    contract_name: []const u8, parent_class: ParentClass = .smart_contract,
    properties: []ANFProperty, constructor: ANFConstructor = .{ .params = &.{}, .assertions = &.{} },
    methods: []ANFMethod,
    pub fn deinit(self: *const ANFProgram, allocator: std.mem.Allocator) void {
        for (self.methods) |method| {
            if (method.bindings.len > 0) freeBindings(allocator, method.bindings);
            if (method.body.len > 0 and method.body.ptr != method.bindings.ptr) freeBindings(allocator, method.body);
        }
        if (self.methods.len > 0) allocator.free(self.methods);
        if (self.properties.len > 0) allocator.free(self.properties);
    }
};
pub const ANFProperty = struct {
    name: []const u8,
    type_name: []const u8 = "",
    type_info: RunarType = .unknown,
    readonly: bool,
    initial_value: ?ConstValue = null,
};
pub const ANFConstructor = struct { params: []ParamNode, assertions: []ANFBinding };
pub const ANFMethod = struct {
    name: []const u8,
    is_public: bool,
    params: []ParamNode = &.{},
    bindings: []ANFBinding = &.{},
    body: []ANFBinding = &.{},
};
pub const ANFBinding = struct { name: []const u8, value: ANFValue, source_loc: ?SourceLocation = null };

pub const ConstValue = union(enum) {
    boolean: bool, integer: i128, string: []const u8,
    pub fn eql(self: ConstValue, other: ConstValue) bool {
        return switch (self) {
            .boolean => |b| switch (other) { .boolean => |ob| b == ob, else => false },
            .integer => |i| switch (other) { .integer => |oi| i == oi, else => false },
            .string => |s| switch (other) { .string => |os| std.mem.eql(u8, s, os), else => false },
        };
    }
};

pub const ANFValue = union(enum) {
    // TypeScript-matching variants (used by stack_lower.zig)
    load_param: LoadParam,
    load_prop: LoadProp,
    load_const: LoadConst,
    bin_op: BinOp,
    unary_op: ANFUnaryOp,
    call: ANFCall,
    method_call: ANFMethodCall,
    @"if": *ANFIf,
    loop: *ANFLoop,
    assert: ANFAssert,
    update_prop: UpdateProp,
    get_state_script: void,
    check_preimage: CheckPreimage,
    deserialize_state: DeserializeState,
    add_output: ANFAddOutput,
    add_raw_output: ANFAddRawOutput,
    array_literal: ANFArrayLiteral,
    // Legacy variants (used by json.zig parser — will be migrated)
    literal_int: i64,
    literal_bigint: []const u8,
    literal_bool: bool,
    literal_bytes: []const u8,
    ref: []const u8,
    property_read: []const u8,
    property_write: PropertyWrite,
    binary_op: ANFBinaryOp,
    builtin_call: ANFBuiltinCall,
    if_expr: *ANFIfExpr,
    for_loop: *ANFForLoop,
    assert_op: ANFLegacyAssert,
    nop: void,
};

// -- TypeScript-matching value structs (used by stack_lower.zig) --
pub const LoadParam = struct { name: []const u8 };
pub const LoadProp = struct { name: []const u8 };
pub const LoadConst = struct { value: ConstValue };
pub const BinOp = struct { op: []const u8, left: []const u8, right: []const u8, result_type: ?[]const u8 = null };
pub const ANFUnaryOp = struct { op: []const u8, operand: []const u8, result_type: ?[]const u8 = null };
pub const ANFCall = struct { func: []const u8, args: []const []const u8 };
pub const ANFMethodCall = struct { object: []const u8, method: []const u8, args: []const []const u8 };
pub const ANFIf = struct { cond: []const u8, then: []ANFBinding, @"else": []ANFBinding };
pub const ANFLoop = struct { count: u32, body: []ANFBinding, iter_var: []const u8 };
pub const ANFAssert = struct { value: []const u8 };
pub const UpdateProp = struct { name: []const u8, value: []const u8 };
pub const CheckPreimage = struct { preimage: []const u8 };
pub const DeserializeState = struct { preimage: []const u8 };
pub const ANFAddOutput = struct { satoshis: []const u8, state_values: []const []const u8 = &.{}, preimage: []const u8 = "", state_refs: []const []const u8 = &.{} };
pub const ANFAddRawOutput = struct { satoshis: []const u8, script_bytes: []const u8 = "", script_ref: []const u8 = "" };
pub const ANFArrayLiteral = struct { elements: []const []const u8 };

// -- Legacy value structs (used by json.zig parser) --
pub const PropertyWrite = struct { name: []const u8, value_ref: []const u8 };
pub const ANFBinaryOp = struct { op: BinOperator, left: []const u8, right: []const u8, result_type: ?[]const u8 = null };
pub const ANFBuiltinCall = struct { name: []const u8, args: []const []const u8 };
pub const ANFIfExpr = struct { condition: []const u8, then_bindings: []ANFBinding, else_bindings: ?[]ANFBinding };
pub const ANFForLoop = struct { var_name: []const u8, init_val: i64, bound: i64, body_bindings: []ANFBinding };
pub const ANFLegacyAssert = struct { condition: []const u8, message: ?[]const u8 = null };

fn freeBindings(allocator: std.mem.Allocator, bindings: []ANFBinding) void {
    for (bindings) |binding| {
        switch (binding.value) {
            .@"if" => |v| { freeBindings(allocator, v.then); freeBindings(allocator, v.@"else"); allocator.destroy(v); },
            .loop => |v| { freeBindings(allocator, v.body); allocator.destroy(v); },
            .if_expr => |v| { freeBindings(allocator, v.then_bindings); if (v.else_bindings) |eb| freeBindings(allocator, eb); allocator.destroy(v); },
            .for_loop => |v| { freeBindings(allocator, v.body_bindings); allocator.destroy(v); },
            else => {},
        }
    }
}

// ============================================================================
// Layer 3: Stack IR Types (output of Pass 5: Stack Lower) — maps to stack-ir.ts
// ============================================================================

pub const StackProgram = struct {
    methods: []StackMethod, contract_name: []const u8,
    properties: []ANFProperty = &.{}, constructor_params: []ParamNode = &.{},
    owned_push_data: [][]u8 = &.{},

    pub fn deinit(self: *const StackProgram, allocator: std.mem.Allocator) void {
        for (self.methods) |method| {
            if (method.instructions.len > 0) allocator.free(method.instructions);
        }
        if (self.methods.len > 0) allocator.free(self.methods);
        for (self.owned_push_data) |data| allocator.free(data);
        if (self.owned_push_data.len > 0) allocator.free(self.owned_push_data);
    }
};
pub const StackMethod = struct {
    name: []const u8,
    /// Flat instruction sequence for direct emission (used by emitMethodScript).
    instructions: []StackInstruction = &.{},
    /// Byte buffers owned by the lowering pass and referenced by `instructions`.
    owned_push_data: [][]u8 = &.{},
    /// High-level stack operations (used by emitDispatchTable, may contain nested if).
    ops: []StackOp = &.{},
    max_stack_depth: u32 = 0,
};

pub const StackOp = union(enum) {
    push: PushValue, dup: void, swap: void, drop: void, nip: void, over: void, rot: void, tuck: void,
    roll: u32, pick: u32, opcode: []const u8, @"if": StackIf, placeholder: Placeholder,
};
pub const StackIf = struct { then: []StackOp, @"else": ?[]StackOp = null };
pub const Placeholder = struct { param_index: u32, param_name: []const u8 };
pub const PushValue = union(enum) { bytes: []const u8, integer: i64, boolean: bool };

pub const StackInstruction = union(enum) { op: Opcode, push_data: []const u8, push_int: i64, push_bool: bool };

// ============================================================================
// Layer 4: Artifact Types (output of Pass 6: Emit) — maps to artifact.ts
// ============================================================================

pub const RunarArtifact = struct {
    version: []const u8, compiler_version: []const u8, contract_name: []const u8,
    abi: ABI, script: []const u8, asm_text: []const u8,
    source_map: ?SourceMap = null, anf: ?*const ANFProgram = null,
    state_fields: ?[]StateField = null, constructor_slots: ?[]ConstructorSlot = null,
    code_separator_index: ?u32 = null, code_separator_indices: ?[]u32 = null,
    build_timestamp: []const u8,
};
pub const Artifact = RunarArtifact;
pub const ABI = struct { constructor: ABIConstructor, methods: []ABIMethod };
pub const ABIConstructor = struct { params: []ABIParam };
pub const ABIMethod = struct { name: []const u8, params: []ABIParam, is_public: bool, is_terminal: bool = false };
pub const ABIParam = struct { name: []const u8, type_name: []const u8 };
pub const ConstructorSlot = struct { param_index: usize, byte_offset: usize };
pub const StateField = struct { name: []const u8, type_name: []const u8, index: usize, initial_value: ?ConstValue = null };
pub const SourceMapping = struct { opcode_index: u32, source_file: []const u8, line: u32, column: u32 };
pub const SourceMap = struct { mappings: []SourceMapping };

// ============================================================================
// Utility
// ============================================================================

const runar_type_map = std.StaticStringMap(RunarType).initComptime(.{
    // Canonical names
    .{ "bigint", .bigint },
    .{ "boolean", .boolean },
    .{ "ByteString", .byte_string },
    .{ "PubKey", .pub_key },
    .{ "Sig", .sig },
    .{ "Addr", .addr },
    .{ "Ripemd160", .ripemd160 },
    .{ "Sha256", .sha256 },
    .{ "SigHashType", .sig_hash_type },
    .{ "SigHashPreimage", .sig_hash_preimage },
    .{ "RabinSig", .rabin_sig },
    .{ "RabinPubKey", .rabin_pub_key },
    .{ "Point", .point },
    .{ "OpCodeType", .op_code_type },
    .{ "void", .void },
    // Aliases
    .{ "int", .bigint },
    .{ "bool", .boolean },
    .{ "bytes", .byte_string },
});

pub fn parseRunarType(type_str: []const u8) RunarType {
    return runar_type_map.get(type_str) orelse .unknown;
}

pub fn runarTypeToString(t: RunarType) []const u8 {
    return switch (t) {
        .bigint => "bigint", .boolean => "boolean", .byte_string => "ByteString",
        .pub_key => "PubKey", .sig => "Sig", .addr => "Addr", .sha256 => "Sha256",
        .ripemd160 => "Ripemd160", .sig_hash_type => "SigHashType",
        .sig_hash_preimage => "SigHashPreimage", .rabin_sig => "RabinSig",
        .rabin_pub_key => "RabinPubKey", .point => "Point", .op_code_type => "OpCodeType",
        .void => "void", .unknown => "unknown",
    };
}

// ============================================================================
// Tests
// ============================================================================

test "ANFProgram basic construction" {
    const program = ANFProgram{ .contract_name = "Test", .parent_class = .stateful_smart_contract, .properties = &.{}, .constructor = .{ .params = &.{}, .assertions = &.{} }, .methods = &.{} };
    try std.testing.expect(program.contract_name.len > 0);
}

test "ANFValue TypeScript-matching variant tags" {
    const variants = [_]ANFValue{
        .{ .load_param = .{ .name = "x" } },
        .{ .load_prop = .{ .name = "y" } },
        .{ .load_const = .{ .value = .{ .integer = 42 } } },
        .{ .bin_op = .{ .op = "+", .left = "a", .right = "b" } },
        .{ .unary_op = .{ .op = "!", .operand = "c" } },
        .{ .call = .{ .func = "hash160", .args = &.{"d"} } },
        .{ .method_call = .{ .object = "e", .method = "unlock", .args = &.{} } },
        .{ .assert = .{ .value = "f" } },
        .{ .update_prop = .{ .name = "counter", .value = "g" } },
        .{ .get_state_script = {} },
        .{ .check_preimage = .{ .preimage = "h" } },
        .{ .deserialize_state = .{ .preimage = "i" } },
        .{ .add_output = .{ .satoshis = "j", .state_values = &.{}, .preimage = "k" } },
        .{ .add_raw_output = .{ .satoshis = "l", .script_bytes = "m" } },
        .{ .array_literal = .{ .elements = &.{ "n", "o" } } },
    };
    try std.testing.expectEqual(@as(usize, 15), variants.len);
}

test "ANFValue legacy variant tags" {
    const variants = [_]ANFValue{
        .{ .literal_int = 42 }, .{ .literal_bigint = "99999" }, .{ .literal_bool = true },
        .{ .literal_bytes = "dead" }, .{ .ref = "t0" }, .{ .property_read = "x" },
        .{ .property_write = .{ .name = "c", .value_ref = "t1" } },
        .{ .binary_op = .{ .op = .add, .left = "a", .right = "b" } },
        .{ .builtin_call = .{ .name = "h", .args = &.{"d"} } },
        .{ .assert_op = .{ .condition = "c" } }, .{ .nop = {} },
    };
    try std.testing.expectEqual(@as(usize, 11), variants.len);
}

test "StackInstruction backward compatibility" {
    const instructions = [_]StackInstruction{ .{ .op = .op_dup }, .{ .op = .op_hash160 }, .{ .push_data = &.{ 0xaa, 0xbb } }, .{ .op = .op_equalverify }, .{ .op = .op_checksig }, .{ .push_int = 42 }, .{ .push_bool = true } };
    try std.testing.expectEqual(@as(usize, 7), instructions.len);
    try std.testing.expectEqual(@as(u8, 0x76), @intFromEnum(Opcode.op_dup));
    try std.testing.expectEqual(@as(u8, 0xac), @intFromEnum(Opcode.op_checksig));
}

test "Opcode aliases" {
    try std.testing.expectEqual(Opcode.op_0, OP_FALSE);
    try std.testing.expectEqual(Opcode.op_1, OP_TRUE);
}

test "BinOperator round-trip" {
    inline for (std.meta.fields(BinOperator)) |field| {
        const op: BinOperator = @enumFromInt(field.value);
        try std.testing.expect(BinOperator.fromTsString(op.toTsString()) != null);
    }
}

test "UnaryOperator round-trip" {
    inline for (std.meta.fields(UnaryOperator)) |field| {
        const op: UnaryOperator = @enumFromInt(field.value);
        try std.testing.expect(UnaryOperator.fromTsString(op.toTsString()) != null);
    }
}

test "PrimitiveTypeName round-trip" {
    inline for (std.meta.fields(PrimitiveTypeName)) |field| {
        const ptn: PrimitiveTypeName = @enumFromInt(field.value);
        try std.testing.expect(PrimitiveTypeName.fromTsString(ptn.toTsString()) != null);
    }
}

test "ParentClass round-trip" {
    try std.testing.expectEqual(ParentClass.smart_contract, ParentClass.fromTsString("SmartContract").?);
    try std.testing.expectEqual(ParentClass.stateful_smart_contract, ParentClass.fromTsString("StatefulSmartContract").?);
}

test "ConstValue equality" {
    try std.testing.expect((ConstValue{ .integer = 42 }).eql(.{ .integer = 42 }));
    try std.testing.expect(!(ConstValue{ .integer = 42 }).eql(.{ .integer = 99 }));
    try std.testing.expect(!(ConstValue{ .integer = 42 }).eql(.{ .boolean = true }));
    try std.testing.expect((ConstValue{ .string = "a" }).eql(.{ .string = "a" }));
}

test "StackOp all variant tags" {
    const ops = [_]StackOp{
        .{ .push = .{ .integer = 42 } }, .{ .dup = {} }, .{ .swap = {} }, .{ .drop = {} },
        .{ .nip = {} }, .{ .over = {} }, .{ .rot = {} }, .{ .tuck = {} },
        .{ .roll = 3 }, .{ .pick = 2 }, .{ .opcode = "OP_ADD" },
        .{ .@"if" = .{ .then = &.{}, .@"else" = null } },
        .{ .placeholder = .{ .param_index = 0, .param_name = "x" } },
    };
    try std.testing.expectEqual(@as(usize, 13), ops.len);
}

test "DiagnosticSeverity and CompilerDiagnostic" {
    const diag = CompilerDiagnostic{ .message = "err", .location = .{ .file = "f", .line = 1, .column = 1 }, .severity = .@"error" };
    try std.testing.expect(diag.location != null);
}

test "runarTypeToString" {
    try std.testing.expectEqualStrings("bigint", runarTypeToString(.bigint));
    try std.testing.expectEqualStrings("PubKey", runarTypeToString(.pub_key));
}

test "parseRunarType canonical names" {
    try std.testing.expectEqual(RunarType.bigint, parseRunarType("bigint"));
    try std.testing.expectEqual(RunarType.boolean, parseRunarType("boolean"));
    try std.testing.expectEqual(RunarType.byte_string, parseRunarType("ByteString"));
    try std.testing.expectEqual(RunarType.pub_key, parseRunarType("PubKey"));
    try std.testing.expectEqual(RunarType.sig, parseRunarType("Sig"));
    try std.testing.expectEqual(RunarType.addr, parseRunarType("Addr"));
    try std.testing.expectEqual(RunarType.void, parseRunarType("void"));
    try std.testing.expectEqual(RunarType.unknown, parseRunarType("NonExistentType"));
}

test "parseRunarType aliases" {
    try std.testing.expectEqual(RunarType.bigint, parseRunarType("int"));
    try std.testing.expectEqual(RunarType.boolean, parseRunarType("bool"));
    try std.testing.expectEqual(RunarType.byte_string, parseRunarType("bytes"));
}

test "typeNodeToRunarType" {
    try std.testing.expectEqual(RunarType.bigint, typeNodeToRunarType(.{ .primitive_type = .bigint }));
    try std.testing.expectEqual(RunarType.pub_key, typeNodeToRunarType(.{ .primitive_type = .pub_key }));
    try std.testing.expectEqual(RunarType.void, typeNodeToRunarType(.{ .primitive_type = .void }));
    try std.testing.expectEqual(RunarType.unknown, typeNodeToRunarType(.{ .custom_type = "MyType" }));
}

test "StateField with initial_value" {
    const field = StateField{ .name = "c", .type_name = "bigint", .index = 0, .initial_value = .{ .integer = 0 } };
    try std.testing.expect(field.initial_value != null);
}
