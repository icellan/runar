const std = @import("std");

// ---------------------------------------------------------------------------
// SDK types for deploying and interacting with compiled Runar contracts on BSV
// ---------------------------------------------------------------------------

/// UTXO represents an unspent transaction output.
pub const UTXO = struct {
    txid: []const u8, // 64-char hex txid
    output_index: i32,
    satoshis: i64,
    script: []const u8, // hex-encoded locking script

    pub fn clone(self: UTXO, allocator: std.mem.Allocator) !UTXO {
        return .{
            .txid = try allocator.dupe(u8, self.txid),
            .output_index = self.output_index,
            .satoshis = self.satoshis,
            .script = try allocator.dupe(u8, self.script),
        };
    }

    pub fn deinit(self: *UTXO, allocator: std.mem.Allocator) void {
        allocator.free(self.txid);
        allocator.free(self.script);
        self.* = .{ .txid = &.{}, .output_index = 0, .satoshis = 0, .script = &.{} };
    }
};

/// TransactionData represents a parsed Bitcoin transaction.
pub const TransactionData = struct {
    txid: []const u8,
    version: i32 = 1,
    inputs: []TxInput = &.{},
    outputs: []TxOutput = &.{},
    locktime: u32 = 0,
    raw: []const u8 = &.{},

    pub fn deinit(self: *TransactionData, allocator: std.mem.Allocator) void {
        if (self.txid.len > 0) allocator.free(self.txid);
        for (self.inputs) |*inp| {
            _ = inp;
        }
        if (self.inputs.len > 0) allocator.free(self.inputs);
        for (self.outputs) |*outp| {
            _ = outp;
        }
        if (self.outputs.len > 0) allocator.free(self.outputs);
        if (self.raw.len > 0) allocator.free(self.raw);
        self.* = .{ .txid = &.{} };
    }
};

/// TxInput represents a transaction input.
pub const TxInput = struct {
    txid: []const u8 = &.{},
    output_index: i32 = 0,
    script: []const u8 = &.{},
    sequence: u32 = 0xffffffff,
};

/// TxOutput represents a transaction output.
pub const TxOutput = struct {
    satoshis: i64 = 0,
    script: []const u8 = &.{}, // hex-encoded locking script
};

/// DeployOptions specifies options for deploying a contract.
pub const DeployOptions = struct {
    satoshis: i64,
    change_address: ?[]const u8 = null,
};

/// CallOptions specifies options for calling a contract method.
pub const CallOptions = struct {
    satoshis: i64 = 0,
    change_address: ?[]const u8 = null,
    new_state: ?[]const StateValue = null,
};

/// ContractOutput describes one contract continuation output.
pub const ContractOutput = struct {
    script: []const u8,
    satoshis: i64,
};

// ---------------------------------------------------------------------------
// Artifact types (compiled contract output)
// ---------------------------------------------------------------------------

/// RunarArtifact is the compiled output of a Runar compiler.
pub const RunarArtifact = struct {
    allocator: std.mem.Allocator,
    version: []const u8 = &.{},
    compiler_version: []const u8 = &.{},
    contract_name: []const u8 = &.{},
    abi: ABI = .{},
    script: []const u8 = &.{},
    asm_text: []const u8 = &.{},
    state_fields: []StateField = &.{},
    constructor_slots: []ConstructorSlot = &.{},
    code_sep_index_slots: []CodeSepIndexSlot = &.{},
    build_timestamp: []const u8 = &.{},
    code_separator_index: ?i32 = null,
    code_separator_indices: []i32 = &.{},
    anf_json: ?[]const u8 = null, // raw JSON of the ANF IR (for SDK auto-state computation)

    pub fn isStateful(self: *const RunarArtifact) bool {
        return self.state_fields.len > 0;
    }

    pub fn deinit(self: *RunarArtifact) void {
        const a = self.allocator;
        if (self.version.len > 0) a.free(self.version);
        if (self.compiler_version.len > 0) a.free(self.compiler_version);
        if (self.contract_name.len > 0) a.free(self.contract_name);
        if (self.script.len > 0) a.free(self.script);
        if (self.asm_text.len > 0) a.free(self.asm_text);
        if (self.build_timestamp.len > 0) a.free(self.build_timestamp);
        self.abi.deinit(a);
        for (self.state_fields) |*sf| sf.deinit(a);
        if (self.state_fields.len > 0) a.free(self.state_fields);
        if (self.constructor_slots.len > 0) a.free(self.constructor_slots);
        if (self.code_sep_index_slots.len > 0) a.free(self.code_sep_index_slots);
        if (self.code_separator_indices.len > 0) a.free(self.code_separator_indices);
        if (self.anf_json) |aj| a.free(aj);
        self.* = .{ .allocator = a };
    }

    /// Parse a RunarArtifact from JSON text.
    pub fn fromJson(allocator: std.mem.Allocator, json_text: []const u8) !RunarArtifact {
        var artifact = RunarArtifact{ .allocator = allocator };
        errdefer artifact.deinit();

        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
        defer parsed.deinit();

        const root = parsed.value.object;

        if (root.get("contractName")) |v| {
            if (v == .string) artifact.contract_name = try allocator.dupe(u8, v.string);
        }
        if (root.get("version")) |v| {
            if (v == .string) artifact.version = try allocator.dupe(u8, v.string);
        }
        if (root.get("compilerVersion")) |v| {
            if (v == .string) artifact.compiler_version = try allocator.dupe(u8, v.string);
        }
        if (root.get("script")) |v| {
            if (v == .string) artifact.script = try allocator.dupe(u8, v.string);
        }
        if (root.get("asm")) |v| {
            if (v == .string) artifact.asm_text = try allocator.dupe(u8, v.string);
        }
        if (root.get("buildTimestamp")) |v| {
            if (v == .string) artifact.build_timestamp = try allocator.dupe(u8, v.string);
        }
        if (root.get("codeSeparatorIndex")) |v| {
            if (v == .integer) artifact.code_separator_index = @intCast(v.integer);
        }
        if (root.get("codeSeparatorIndices")) |v| {
            if (v == .array) {
                const items = v.array.items;
                var indices = try allocator.alloc(i32, items.len);
                for (items, 0..) |item, i| {
                    indices[i] = if (item == .integer) @intCast(item.integer) else 0;
                }
                artifact.code_separator_indices = indices;
            }
        }

        // Parse ABI
        if (root.get("abi")) |abi_val| {
            if (abi_val == .object) {
                artifact.abi = try ABI.fromJsonValue(allocator, abi_val.object);
            }
        }

        // Parse stateFields
        if (root.get("stateFields")) |sf_val| {
            if (sf_val == .array) {
                const items = sf_val.array.items;
                var fields = try allocator.alloc(StateField, items.len);
                for (items, 0..) |item, i| {
                    fields[i] = try StateField.fromJsonValue(allocator, item.object);
                }
                artifact.state_fields = fields;
            }
        }

        // Store raw ANF JSON for the SDK ANF interpreter
        if (root.get("anf")) |anf_val| {
            if (anf_val == .object) {
                // Re-stringify the ANF object so the interpreter can parse it independently
                const anf_str = std.json.Stringify.valueAlloc(allocator, anf_val, .{}) catch null;
                if (anf_str) |s| {
                    artifact.anf_json = s;
                }
            }
        }

        // Parse constructorSlots
        if (root.get("constructorSlots")) |cs_val| {
            if (cs_val == .array) {
                const items = cs_val.array.items;
                var slots = try allocator.alloc(ConstructorSlot, items.len);
                for (items, 0..) |item, i| {
                    const obj = item.object;
                    slots[i] = .{
                        .param_index = if (obj.get("paramIndex")) |pi| @intCast(pi.integer) else 0,
                        .byte_offset = if (obj.get("byteOffset")) |bo| @intCast(bo.integer) else 0,
                    };
                }
                artifact.constructor_slots = slots;
            }
        }

        // Parse codeSepIndexSlots
        if (root.get("codeSepIndexSlots")) |csis_val| {
            if (csis_val == .array) {
                const items = csis_val.array.items;
                var csis = try allocator.alloc(CodeSepIndexSlot, items.len);
                for (items, 0..) |item, i| {
                    const obj = item.object;
                    csis[i] = .{
                        .byte_offset = if (obj.get("byteOffset")) |bo| @intCast(bo.integer) else 0,
                        .code_sep_index = if (obj.get("codeSepIndex")) |ci| @intCast(ci.integer) else 0,
                    };
                }
                artifact.code_sep_index_slots = csis;
            }
        }

        return artifact;
    }
};

/// ABI describes the contract's public interface.
pub const ABI = struct {
    constructor: ABIConstructor = .{},
    methods: []ABIMethod = &.{},

    pub fn deinit(self: *ABI, allocator: std.mem.Allocator) void {
        self.constructor.deinit(allocator);
        for (self.methods) |*m| m.deinit(allocator);
        if (self.methods.len > 0) allocator.free(self.methods);
        self.* = .{};
    }

    pub fn fromJsonValue(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !ABI {
        var abi = ABI{};
        errdefer abi.deinit(allocator);

        if (obj.get("constructor")) |ctor_val| {
            if (ctor_val == .object) {
                abi.constructor = try ABIConstructor.fromJsonValue(allocator, ctor_val.object);
            }
        }

        if (obj.get("methods")) |methods_val| {
            if (methods_val == .array) {
                const items = methods_val.array.items;
                var methods = try allocator.alloc(ABIMethod, items.len);
                errdefer allocator.free(methods);
                for (items, 0..) |item, i| {
                    methods[i] = try ABIMethod.fromJsonValue(allocator, item.object);
                }
                abi.methods = methods;
            }
        }

        return abi;
    }
};

/// ABIConstructor describes the constructor parameters.
pub const ABIConstructor = struct {
    params: []ABIParam = &.{},

    pub fn deinit(self: *ABIConstructor, allocator: std.mem.Allocator) void {
        for (self.params) |*p| p.deinit(allocator);
        if (self.params.len > 0) allocator.free(self.params);
        self.* = .{};
    }

    pub fn fromJsonValue(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !ABIConstructor {
        var ctor = ABIConstructor{};
        if (obj.get("params")) |params_val| {
            if (params_val == .array) {
                const items = params_val.array.items;
                var params = try allocator.alloc(ABIParam, items.len);
                for (items, 0..) |item, i| {
                    params[i] = try ABIParam.fromJsonValue(allocator, item.object);
                }
                ctor.params = params;
            }
        }
        return ctor;
    }
};

/// ABIMethod describes a contract method.
pub const ABIMethod = struct {
    name: []const u8 = &.{},
    params: []ABIParam = &.{},
    is_public: bool = false,
    is_terminal: ?bool = null,

    pub fn deinit(self: *ABIMethod, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(self.name);
        for (self.params) |*p| p.deinit(allocator);
        if (self.params.len > 0) allocator.free(self.params);
        self.* = .{};
    }

    pub fn fromJsonValue(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !ABIMethod {
        var method = ABIMethod{};
        errdefer method.deinit(allocator);

        if (obj.get("name")) |v| {
            if (v == .string) method.name = try allocator.dupe(u8, v.string);
        }
        if (obj.get("isPublic")) |v| {
            if (v == .bool) method.is_public = v.bool;
        }
        if (obj.get("isTerminal")) |v| {
            if (v == .bool) method.is_terminal = v.bool;
        }
        if (obj.get("params")) |params_val| {
            if (params_val == .array) {
                const items = params_val.array.items;
                var params = try allocator.alloc(ABIParam, items.len);
                for (items, 0..) |item, i| {
                    params[i] = try ABIParam.fromJsonValue(allocator, item.object);
                }
                method.params = params;
            }
        }

        return method;
    }
};

/// ABIParam describes a single parameter.
pub const ABIParam = struct {
    name: []const u8 = &.{},
    type_name: []const u8 = &.{},

    pub fn deinit(self: *ABIParam, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(self.name);
        if (self.type_name.len > 0) allocator.free(self.type_name);
        self.* = .{};
    }

    pub fn fromJsonValue(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !ABIParam {
        var param = ABIParam{};
        errdefer param.deinit(allocator);

        if (obj.get("name")) |v| {
            if (v == .string) param.name = try allocator.dupe(u8, v.string);
        }
        if (obj.get("type")) |v| {
            if (v == .string) param.type_name = try allocator.dupe(u8, v.string);
        }

        return param;
    }
};

/// FixedArrayInfo carries the metadata the SDK needs to flatten nested
/// FixedArray state values into their scalar leaf slots at encode time and
/// regroup them back at decode time. Populated from the `fixedArray` object
/// on a StateField JSON entry when the compiler emits one.
pub const FixedArrayInfo = struct {
    element_type: []const u8 = &.{},
    length: u32 = 0,
    synthetic_names: [][]const u8 = &.{},

    pub fn deinit(self: *FixedArrayInfo, allocator: std.mem.Allocator) void {
        if (self.element_type.len > 0) allocator.free(self.element_type);
        for (self.synthetic_names) |n| allocator.free(n);
        if (self.synthetic_names.len > 0) allocator.free(self.synthetic_names);
        self.* = .{};
    }
};

/// StateField describes a state field in a stateful contract.
pub const StateField = struct {
    name: []const u8 = &.{},
    type_name: []const u8 = &.{},
    index: i32 = 0,
    initial_value: ?[]const u8 = null, // stored as string representation
    /// When non-null, this state field is a logical FixedArray that expands
    /// into `fixed_array.synthetic_names.len` scalar slots. The SDK flattens
    /// array-typed state values on write and regroups them on read.
    fixed_array: ?FixedArrayInfo = null,

    pub fn deinit(self: *StateField, allocator: std.mem.Allocator) void {
        if (self.name.len > 0) allocator.free(self.name);
        if (self.type_name.len > 0) allocator.free(self.type_name);
        if (self.initial_value) |iv| allocator.free(iv);
        if (self.fixed_array) |*fa| fa.deinit(allocator);
        self.* = .{};
    }

    pub fn fromJsonValue(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !StateField {
        var field = StateField{};
        errdefer field.deinit(allocator);

        if (obj.get("name")) |v| {
            if (v == .string) field.name = try allocator.dupe(u8, v.string);
        }
        if (obj.get("type")) |v| {
            if (v == .string) field.type_name = try allocator.dupe(u8, v.string);
        }
        if (obj.get("index")) |v| {
            if (v == .integer) field.index = @intCast(v.integer);
        }
        if (obj.get("initialValue")) |v| {
            switch (v) {
                .string => |s| field.initial_value = try allocator.dupe(u8, s),
                .integer => |n| {
                    field.initial_value = try std.fmt.allocPrint(allocator, "{d}", .{n});
                },
                .bool => |b| {
                    field.initial_value = try allocator.dupe(u8, if (b) "true" else "false");
                },
                else => {},
            }
        }
        if (obj.get("fixedArray")) |v| {
            if (v == .object) {
                var fa = FixedArrayInfo{};
                errdefer fa.deinit(allocator);
                if (v.object.get("elementType")) |et| {
                    if (et == .string) fa.element_type = try allocator.dupe(u8, et.string);
                }
                if (v.object.get("length")) |ln| {
                    if (ln == .integer) fa.length = @intCast(ln.integer);
                }
                if (v.object.get("syntheticNames")) |sn| {
                    if (sn == .array) {
                        var names = try allocator.alloc([]const u8, sn.array.items.len);
                        var filled: usize = 0;
                        errdefer {
                            for (0..filled) |i| allocator.free(names[i]);
                            allocator.free(names);
                        }
                        for (sn.array.items) |it| {
                            if (it == .string) {
                                names[filled] = try allocator.dupe(u8, it.string);
                                filled += 1;
                            }
                        }
                        fa.synthetic_names = names;
                    }
                }
                field.fixed_array = fa;
            }
        }

        return field;
    }
};

/// ConstructorSlot describes where a constructor parameter placeholder
/// resides in the compiled script (byte offset of the OP_0 placeholder).
pub const ConstructorSlot = struct {
    param_index: i32,
    byte_offset: i32,
};

/// CodeSepIndexSlot describes where a codeSeparatorIndex placeholder (OP_0)
/// resides in the template script. The SDK substitutes these at deployment
/// time with the adjusted codeSeparatorIndex value that accounts for
/// constructor arg expansion.
pub const CodeSepIndexSlot = struct {
    byte_offset: i32,
    code_sep_index: i32,
};

// ---------------------------------------------------------------------------
// StateValue — dynamically-typed value used in contract state
// ---------------------------------------------------------------------------

/// StateValue is a tagged union for contract state values and method arguments.
pub const StateValue = union(enum) {
    int: i64,
    /// Arbitrary-precision integer stored as a decimal string (owned).
    /// Used for values that exceed the i64 range.
    big_int: []const u8,
    boolean: bool,
    bytes: []const u8, // hex-encoded
    /// A (possibly nested) array of scalar StateValues — produced when the
    /// SDK deserializes a FixedArray state field, or passed by the user when
    /// constructing such a field. Leaves may only be scalar StateValues; the
    /// flatten/regroup helpers in `sdk_state.zig` walk the tree linearly.
    array_value: []const StateValue,

    pub fn deinit(self: StateValue, allocator: std.mem.Allocator) void {
        switch (self) {
            .bytes => |b| allocator.free(b),
            .big_int => |s| allocator.free(s),
            .array_value => |items| {
                for (items) |it| it.deinit(allocator);
                allocator.free(items);
            },
            else => {},
        }
    }

    pub fn clone(self: StateValue, allocator: std.mem.Allocator) !StateValue {
        return switch (self) {
            .int => |n| .{ .int = n },
            .big_int => |s| .{ .big_int = try allocator.dupe(u8, s) },
            .boolean => |b| .{ .boolean = b },
            .bytes => |b| .{ .bytes = try allocator.dupe(u8, b) },
            .array_value => |items| blk: {
                var copy = try allocator.alloc(StateValue, items.len);
                for (items, 0..) |it, i| copy[i] = try it.clone(allocator);
                break :blk .{ .array_value = copy };
            },
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "RunarArtifact.fromJson parses minimal artifact" {
    const json =
        \\{"contractName":"Test","version":"1","compilerVersion":"1.0","script":"5100","asm":"OP_1 OP_0",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try RunarArtifact.fromJson(std.testing.allocator, json);
    defer artifact.deinit();

    try std.testing.expectEqualStrings("Test", artifact.contract_name);
    try std.testing.expectEqualStrings("5100", artifact.script);
    try std.testing.expectEqual(@as(usize, 1), artifact.abi.methods.len);
    try std.testing.expectEqualStrings("unlock", artifact.abi.methods[0].name);
    try std.testing.expect(artifact.abi.methods[0].is_public);
}

test "RunarArtifact.fromJson parses stateful artifact with constructor slots" {
    const json =
        \\{"contractName":"Counter","version":"1","compilerVersion":"1.0","script":"005100","asm":"OP_0 OP_1 OP_0",
        \\"abi":{"constructor":{"params":[{"name":"count","type":"int"}]},"methods":[{"name":"increment","params":[],"isPublic":true}]},
        \\"stateFields":[{"name":"count","type":"int","index":0}],
        \\"constructorSlots":[{"paramIndex":0,"byteOffset":0}],
        \\"codeSeparatorIndex":2,"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try RunarArtifact.fromJson(std.testing.allocator, json);
    defer artifact.deinit();

    try std.testing.expectEqualStrings("Counter", artifact.contract_name);
    try std.testing.expectEqual(@as(usize, 1), artifact.state_fields.len);
    try std.testing.expectEqualStrings("count", artifact.state_fields[0].name);
    try std.testing.expectEqual(@as(usize, 1), artifact.constructor_slots.len);
    try std.testing.expectEqual(@as(i32, 0), artifact.constructor_slots[0].byte_offset);
    try std.testing.expectEqual(@as(i32, 2), artifact.code_separator_index.?);
    try std.testing.expect(artifact.isStateful());
}
