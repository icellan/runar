//! Pass 2: Validate — checks a ContractNode against Runar language constraints.
//!
//! Takes the AST produced by Pass 1 (Parse) and reports errors/warnings WITHOUT
//! modifying it. Direct port of compilers/python/runar_compiler/frontend/validator.py.
//!
//! Checks performed:
//!   1. Valid property types (no void, positive array lengths, no custom types)
//!   2. SmartContract: all properties must be readonly
//!   3. StatefulSmartContract: warn if no mutable properties
//!   4. StatefulSmartContract: txPreimage must not be declared (implicit)
//!   5. Constructor must have super() call and assign all properties
//!   6. No recursion (build call graph, DFS cycle detection)
//!   7. Public methods must end with assert (stateless contracts)
//!   8. StatefulSmartContract: warn on manual checkPreimage/getStateScript

const std = @import("std");
const types = @import("../ir/types.zig");
const sighash_validate = @import("sighash_validate.zig");

const Allocator = std.mem.Allocator;
const ContractNode = types.ContractNode;
const PropertyNode = types.PropertyNode;
const ConstructorNode = types.ConstructorNode;
const MethodNode = types.MethodNode;
const Expression = types.Expression;
const Statement = types.Statement;
const RunarType = types.RunarType;
const ParentClass = types.ParentClass;
const CompilerDiagnostic = types.CompilerDiagnostic;
const DiagnosticSeverity = types.DiagnosticSeverity;

// ============================================================================
// Public API
// ============================================================================

pub const ValidationResult = struct {
    errors: []CompilerDiagnostic,
    warnings: []CompilerDiagnostic,
};

const ConstructorValidationMode = enum {
    generic,
    zig,
};

/// Validate a Runar AST against language subset constraints.
/// Does NOT modify the AST; only reports errors and warnings.
/// Caller owns the returned slices and must free them with the same allocator.
pub fn validate(allocator: Allocator, contract: ContractNode) !ValidationResult {
    return validateWithMode(allocator, contract, .generic);
}

/// Validate a Zig AST against Runar language subset constraints.
/// Zig constructors use `init` field assignment, not `super(...)`.
pub fn validateZig(allocator: Allocator, contract: ContractNode) !ValidationResult {
    return validateWithMode(allocator, contract, .zig);
}

fn validateWithMode(
    allocator: Allocator,
    contract: ContractNode,
    mode: ConstructorValidationMode,
) !ValidationResult {
    var errors: std.ArrayListUnmanaged(CompilerDiagnostic) = .empty;
    defer errors.deinit(allocator);
    var warnings: std.ArrayListUnmanaged(CompilerDiagnostic) = .empty;
    defer warnings.deinit(allocator);

    try validateProperties(allocator, contract, &errors, &warnings);
    try validateConstructor(allocator, contract, mode, &errors);
    try validateMethods(allocator, contract, &errors, &warnings);
    try checkNoRecursion(allocator, contract, &errors);

    // Issue #123: reject preimage-field reads / output bindings that are
    // unsound under a method's declared @sighash mode (security core). The pass
    // emits both errors (unsound usages) and warnings (e.g. an explicit
    // single-output SINGLE covenant whose same-index value cannot be pinned
    // statically), so route each diagnostic to the matching bucket.
    {
        var sighash_diags: std.ArrayListUnmanaged(CompilerDiagnostic) = .empty;
        defer sighash_diags.deinit(allocator);
        try sighash_validate.validateSighashUsage(allocator, contract, &sighash_diags);
        for (sighash_diags.items) |d| {
            if (d.severity == .warning) {
                try warnings.append(allocator, d);
            } else {
                try errors.append(allocator, d);
            }
        }
    }

    return .{
        .errors = try errors.toOwnedSlice(allocator),
        .warnings = try warnings.toOwnedSlice(allocator),
    };
}

/// Free a ValidationResult previously returned by validate().
pub fn freeResult(allocator: Allocator, result: ValidationResult) void {
    // Diagnostics whose message was allocPrint'd carry `owned_message`; static
    // literals leave it false and must not be freed.
    for (result.errors) |d| if (d.owned_message) allocator.free(d.message);
    for (result.warnings) |d| if (d.owned_message) allocator.free(d.message);
    allocator.free(result.errors);
    allocator.free(result.warnings);
}

// ============================================================================
// Valid property types
// ============================================================================

/// Property types that are valid in Runar contracts. Void is explicitly excluded.
fn isValidPropertyType(t: RunarType) bool {
    return switch (t) {
        .bigint, .boolean, .byte_string, .pub_key, .sig, .sha256, .ripemd160,
        .addr, .sig_hash_preimage, .rabin_sig, .rabin_pub_key, .point,
        .p256_point, .p384_point,
        .fixed_array,
        => true,
        .void, .unknown, .op_code_type, .sig_hash_type => false,
    };
}

// ============================================================================
// Property validation
// ============================================================================

fn validateProperties(
    allocator: Allocator,
    contract: ContractNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
    warnings: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    for (contract.properties) |prop| {
        // Check for void type
        if (prop.type_info == .void) {
            try errors.append(allocator, .{
                .message = "property type 'void' is not valid",
                .severity = .@"error",
            });
        } else if (!isValidPropertyType(prop.type_info) and prop.type_info != .unknown) {
            try errors.append(allocator, .{
                .message = "unsupported type in property declaration",
                .severity = .@"error",
            });
        }

        // FixedArray-specific validation
        if (prop.type_info == .fixed_array) {
            if (prop.fixed_array_length == 0) {
                try errors.append(allocator, .{
                    .message = "FixedArray length must be a positive integer",
                    .severity = .@"error",
                });
            }
            if (prop.fixed_array_element == .void) {
                try errors.append(allocator, .{
                    .message = "FixedArray element type cannot be 'void'",
                    .severity = .@"error",
                });
            }
            if (prop.initializer) |init_expr| {
                if (init_expr != .array_literal) {
                    try errors.append(allocator, .{
                        .message = "FixedArray property must use an array-literal initializer",
                        .severity = .@"error",
                    });
                } else if (!isArrayLiteralOfLiterals(init_expr)) {
                    try errors.append(allocator, .{
                        .message = "property initializer must be an array literal of literal values",
                        .severity = .@"error",
                    });
                }
            }
        } else if (prop.initializer) |init_expr| {
            // Property initializers are restricted to literal values. Mirrors
            // the TS validator in `02-validate.ts` and the Go peer in
            // `validator.go` — without this a non-literal default (e.g.
            // `1n + 2n`) compiled straight through to a deployable script.
            if (!isLiteralExpression(init_expr)) {
                try errors.append(allocator, .{
                    .message = "property initializer must be a literal value",
                    .severity = .@"error",
                });
            }
        }

        // V27: txPreimage is implicit in StatefulSmartContract
        if (contract.parent_class == .stateful_smart_contract and
            std.mem.eql(u8, prop.name, "txPreimage"))
        {
            try errors.append(allocator, .{
                .message = "'txPreimage' is an implicit property of StatefulSmartContract and must not be declared",
                .severity = .@"error",
            });
        }
    }

    // SmartContract (and the asm-escape-hatch UnsafeSmartContract) require all
    // properties to be readonly.
    if (contract.parent_class == .smart_contract or contract.parent_class == .unsafe_smart_contract) {
        for (contract.properties) |prop| {
            if (!prop.readonly) {
                try errors.append(allocator, .{
                    .message = "property in SmartContract must be declared readonly",
                    .severity = .@"error",
                });
            }
        }
    }

    // V26: Warn if StatefulSmartContract has no mutable properties
    if (contract.parent_class == .stateful_smart_contract) {
        var has_mutable = false;
        for (contract.properties) |prop| {
            if (!prop.readonly) {
                has_mutable = true;
                break;
            }
        }
        if (!has_mutable) {
            try warnings.append(allocator, .{
                .message = "StatefulSmartContract has no mutable properties; consider using SmartContract instead",
                .severity = .warning,
            });
        }
    }
}

// ============================================================================
// Constructor validation
// ============================================================================

/// Whether an expression is a literal allowed as a property initializer
/// (bigint, bool, bytestring, or a negated bigint literal). Mirrors the TS/Go
/// validator helpers.
fn isLiteralExpression(expr: Expression) bool {
    return switch (expr) {
        .literal_int, .literal_bigint, .literal_bool, .literal_bytes => true,
        .unary_op => |u| u.op == .negate and switch (u.operand) {
            .literal_int, .literal_bigint => true,
            else => false,
        },
        else => false,
    };
}

/// Whether an expression is an array literal whose elements are all literal
/// values (recursively, for nested FixedArray initializers).
fn isArrayLiteralOfLiterals(expr: Expression) bool {
    const elements = switch (expr) {
        .array_literal => |els| els,
        else => return false,
    };
    for (elements) |el| {
        if (el == .array_literal) {
            if (!isArrayLiteralOfLiterals(el)) return false;
        } else if (!isLiteralExpression(el)) {
            return false;
        }
    }
    return true;
}

fn validateConstructor(
    allocator: Allocator,
    contract: ContractNode,
    mode: ConstructorValidationMode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    const ctor = contract.constructor;
    const is_zig_constructor = mode == .zig or isZigConstructor(ctor);

    if (!is_zig_constructor and ctor.params.len > 0 and ctor.super_args.len == 0) {
        try errors.append(allocator, .{
            .message = "constructor must call super() with all parameters",
            .severity = .@"error",
        });
    }

    for (contract.properties) |prop| {
        var assigned = false;
        for (ctor.assignments) |assignment| {
            if (std.mem.eql(u8, assignment.target, prop.name)) {
                assigned = true;
                break;
            }
        }
        // Properties with initializers don't need constructor assignments
        if (!assigned and prop.initializer == null) {
            try errors.append(allocator, .{
                .message = "property must be assigned in the constructor",
                .severity = .@"error",
            });
        }
    }

    try validateConstructorSlotBijection(allocator, contract, errors);
}

/// Distinct bare constructor parameters the constructor assigns to one
/// property, mirroring the TS `propToParams` map entry for that property: a
/// non-parameter assignment (an assigned literal is not a deploy-time
/// argument) RESETS the set.
const PropAssignment = struct {
    /// The constructor assigns the property at least once.
    present: bool,
    /// Number of DISTINCT parameters currently assigned (capped at 2).
    count: usize,
    /// The single parameter, when `count == 1`.
    param: ?[]const u8,
};

fn propAssignedParams(contract: ContractNode, prop_name: []const u8) PropAssignment {
    var out = PropAssignment{ .present = false, .count = 0, .param = null };
    for (contract.constructor.assignments) |a| {
        if (!std.mem.eql(u8, a.target, prop_name)) continue;
        out.present = true;
        switch (a.value) {
            .identifier => |name| {
                if (!isCtorParam(contract, name)) {
                    out.count = 0;
                    out.param = null;
                    continue;
                }
                if (out.param) |p| {
                    if (!std.mem.eql(u8, p, name)) out.count = 2;
                } else {
                    out.param = name;
                    out.count = 1;
                }
            },
            else => {
                out.count = 0;
                out.param = null;
            },
        }
    }
    return out;
}

fn isCtorParam(contract: ContractNode, name: []const u8) bool {
    for (contract.constructor.params) |p| {
        if (std.mem.eql(u8, p.name, name)) return true;
    }
    return false;
}

fn ctorParamIndex(contract: ContractNode, name: []const u8) ?usize {
    for (contract.constructor.params, 0..) |p, i| {
        if (std.mem.eql(u8, p.name, name)) return i;
    }
    return null;
}

/// Distinct properties a constructor parameter is assigned to, appended to
/// `out` in constructor-body order.
fn paramFedProps(
    allocator: Allocator,
    contract: ContractNode,
    param_name: []const u8,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    for (contract.constructor.assignments) |a| {
        switch (a.value) {
            .identifier => |name| {
                if (!std.mem.eql(u8, name, param_name)) continue;
                var seen = false;
                for (out.items) |existing| {
                    if (std.mem.eql(u8, existing, a.target)) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) try out.append(allocator, a.target);
            },
            else => {},
        }
    }
}

/// Enforce the NEW-002 invariant: every constructor parameter initialises
/// exactly one property that needs a deploy-time value, and the i-th parameter
/// initialises the i-th such property.
///
/// A property's deploy-time value comes from a constructor ARGUMENT, and the
/// artifact addresses those arguments POSITIONALLY: the ABI constructor params
/// come from the constructor SIGNATURE while a constructor slot's `paramIndex`
/// is an index into the properties with no `initialValue`, and the SDK splices
/// `constructorArgs[slot.paramIndex]` into the slot's bytes. Two independently
/// built lists, assumed to line up. Where they disagree a deploy argument lands
/// in ANOTHER property's slot, silently — a deployed contract authorising a
/// value the developer never passed for that property.
///
/// "Needs a deploy-time value" mirrors `constructorAssignsUniquely` in
/// `anf_lower.zig` exactly: a property carries a compile-time `initial_value`
/// iff it has an initializer the constructor does NOT override by assigning it
/// a bare parameter.
fn validateConstructorSlotBijection(
    allocator: Allocator,
    contract: ContractNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    const ctor = contract.constructor;
    const before = errors.items.len;

    // (a) One parameter feeding several properties: only one of them could own
    // the argument, so the rest keep a default or deploy undefined.
    for (ctor.params) |param| {
        var fed: std.ArrayListUnmanaged([]const u8) = .empty;
        defer fed.deinit(allocator);
        try paramFedProps(allocator, contract, param.name, &fed);
        if (fed.items.len <= 1) continue;
        const joined = try std.mem.join(allocator, ", ", fed.items);
        defer allocator.free(joined);
        try errors.append(allocator, .{
            .message = try std.fmt.allocPrint(
                allocator,
                "constructor parameter '{s}' initialises more than one property ({s}). Each constructor parameter is spliced into exactly one property's deploy-time slot, so only the first would receive the argument. Declare one parameter per property.",
                .{ param.name, joined },
            ),
            .owned_message = true,
            .severity = .@"error",
        });
    }

    // (b) One property fed by several parameters — no single argument owns it.
    for (contract.properties) |prop| {
        const info = propAssignedParams(contract, prop.name);
        if (info.count <= 1) continue;
        try errors.append(allocator, .{
            .message = try std.fmt.allocPrint(
                allocator,
                "property '{s}' is assigned more than one constructor parameter. Each property that needs a deploy-time value corresponds to exactly one constructor parameter.",
                .{prop.name},
            ),
            .owned_message = true,
            .severity = .@"error",
        });
    }

    // (c) A property that needs a deploy-time value but whose constructor
    // assignment is not a parameter. A property assigned NOTHING is already
    // reported above, so it is skipped here rather than double-reported.
    for (contract.properties) |prop| {
        if (prop.initializer != null) continue;
        const info = propAssignedParams(contract, prop.name);
        if (!info.present or info.count >= 1) continue;
        try errors.append(allocator, .{
            .message = try std.fmt.allocPrint(
                allocator,
                "property '{s}' has no initializer and is not assigned a constructor parameter, so it has no deploy-time value. The constructor body is not compiled into the locking script — give the property a literal initializer or assign it a constructor parameter (this.{s} = {s}).",
                .{ prop.name, prop.name, prop.name },
            ),
            .owned_message = true,
            .severity = .@"error",
        });
    }

    // (d) A parameter that initialises nothing: its argument is dropped and,
    // because slots are positional, every later argument lands in the wrong slot.
    for (ctor.params) |param| {
        var fed: std.ArrayListUnmanaged([]const u8) = .empty;
        defer fed.deinit(allocator);
        try paramFedProps(allocator, contract, param.name, &fed);
        if (fed.items.len > 0) continue;
        try errors.append(allocator, .{
            .message = try std.fmt.allocPrint(
                allocator,
                "constructor parameter '{s}' does not initialise any property. Constructor arguments are spliced into property slots positionally, so an unused parameter drops its own argument and shifts every later one into the wrong property's slot. Assign it (this.{s} = {s}) or remove the parameter.",
                .{ param.name, param.name, param.name },
            ),
            .owned_message = true,
            .severity = .@"error",
        });
    }

    // (e) Order. Only meaningful once (a)-(d) hold, otherwise the positions
    // being compared are themselves the thing that is broken.
    if (errors.items.len != before) return;
    var slot: usize = 0;
    for (contract.properties) |prop| {
        const info = propAssignedParams(contract, prop.name);
        const single: ?[]const u8 = if (info.count == 1) info.param else null;
        if (prop.initializer != null and single == null) continue;
        if (single) |param| {
            const declared = ctorParamIndex(contract, param) orelse continue;
            if (declared != slot) {
                const abi_name = if (slot < ctor.params.len) ctor.params[slot].name else "?";
                try errors.append(allocator, .{
                    .message = try std.fmt.allocPrint(
                        allocator,
                        "property '{s}' occupies deploy-time slot {d}, but the constructor parameter that initialises it ('{s}') is declared at position {d}. Constructor arguments are spliced positionally, so the deployed script would carry argument {d} — advertised by the ABI as parameter '{s}' — in this property's slot. Declare the parameters in the same order as the properties they initialise.",
                        .{ prop.name, slot, param, declared, slot, abi_name },
                    ),
                    .owned_message = true,
                    .severity = .@"error",
                });
            }
        }
        slot += 1;
    }
}

fn isZigConstructor(ctor: ConstructorNode) bool {
    for (ctor.params) |param| {
        if (param.type_name.len == 0) return true;
    }
    return false;
}

// ============================================================================
// Method validation
// ============================================================================

fn validateMethods(
    allocator: Allocator,
    contract: ContractNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
    warnings: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    // A contract with no public methods has no spending entry points and
    // compiles to an empty script — never what the author meant (usually a
    // missing `public` modifier; methods default to private).
    var has_public = false;
    for (contract.methods) |method| {
        if (method.is_public) {
            has_public = true;
            break;
        }
    }
    if (!has_public) {
        try errors.append(allocator, .{
            .message = "Contract has no public methods — no spending entry points; add 'public' to at least one method",
            .severity = .@"error",
        });
    }

    for (contract.methods) |method| {
        // FixedArray may not appear as a method parameter.
        for (method.params) |p| {
            if (p.type_info == .fixed_array) {
                try errors.append(allocator, .{
                    .message = "FixedArray is not allowed as a method parameter",
                    .severity = .@"error",
                });
            }
        }

        // `return` is a PRIVATE-helper construct only (NEW-012).
        if (method.is_public) {
            var returns: usize = 0;
            countReturnStatements(method.body, &returns);
            var i: usize = 0;
            while (i < returns) : (i += 1) {
                try errors.append(allocator, .{
                    .message = try std.fmt.allocPrint(
                        allocator,
                        "public method '{s}' must not use `return`: public methods are spending entry points, they return void (spec/grammar.md:161) and must end with an assert() that encodes the spending condition (spec/grammar.md:162). R\u{00fa}nar has no early exit \u{2014} restructure the guard as an if/else, or move the logic into a private helper, where `return` is allowed.",
                        .{method.name},
                    ),
                    .owned_message = true,
                    .severity = .@"error",
                });
            }
        }

        // Public methods must end with an assert() call. For
        // StatefulSmartContract the compiler auto-injects the final assert.
        // For UnsafeSmartContract a terminal asm({..., out_arity: 1}) also
        // counts — either way the script must leave a truthy value on the
        // stack.
        if (method.is_public and contract.parent_class == .smart_contract) {
            if (!endsWithAssert(method.body)) {
                try errors.append(allocator, .{
                    .message = "public method must end with an assert() call",
                    .severity = .@"error",
                });
            }
        }
        if (method.is_public and contract.parent_class == .unsafe_smart_contract) {
            if (!endsWithAssert(method.body) and !endsWithTerminalAsm(method.body)) {
                try errors.append(allocator, .{
                    .message = "public method in UnsafeSmartContract must end with an assert() call or a terminal asm({...}) with out_arity 1",
                    .severity = .@"error",
                });
            }
        }

        // V24/V25: Warn on manual preimage/state-script boilerplate in StatefulSmartContract
        if (contract.parent_class == .stateful_smart_contract and method.is_public) {
            try warnManualPreimageUsage(allocator, method, warnings);
        }

        // #131: warn when a public method gates on extractLocktime but never
        // asserts the spending tx is non-final (extractSequence < 0xffffffff).
        // Advisory only — no effect on emitted bytecode.
        if (method.is_public) {
            try warnLocktimeWithoutSequenceGuard(allocator, contract, method, warnings);
        }

        // Gate asm({...}) calls on UnsafeSmartContract + check structural args.
        try validateAsmUsage(allocator, contract, method, errors);

        // readonly properties may only be assigned in the constructor.
        try checkReadonlyWrites(allocator, contract, method, errors);

        // Validate for-loop bounds are compile-time constants
        for (method.body) |stmt| {
            try validateStatement(allocator, stmt, errors);
        }
    }
}

/// Report every write to a `readonly` contract property in a method body.
///
/// spec/semantics.md:
///   <this.p = e, env, sigma> ==> ERROR: cannot assign to readonly property
///
/// The constructor is exempt — that is where every contract initialises its
/// readonly properties. In this tier `ConstructorNode` carries `assignments`
/// rather than statements, so constructor writes never reach the statement
/// walk and no explicit exemption is needed.
///
/// `Assign.target` is a bare name with the `this.` already stripped, so the
/// check keys off `Assign.target_is_property` (set by every surface parser)
/// rather than the name alone — otherwise a local shadowing a readonly
/// property name would be rejected, diverging from the other six tiers.
/// `this.p++` / `this.p--` carry a full `property_access` operand and are
/// matched structurally.
fn checkReadonlyWrites(
    allocator: Allocator,
    contract: ContractNode,
    method: MethodNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    var has_readonly = false;
    for (contract.properties) |p| {
        if (p.readonly) {
            has_readonly = true;
            break;
        }
    }
    if (!has_readonly) return;

    try walkReadonlyWrites(allocator, contract, method.body, errors);
}

fn isReadonlyPropertyName(contract: ContractNode, name: []const u8) bool {
    for (contract.properties) |p| {
        if (std.mem.eql(u8, p.name, name)) return p.readonly;
    }
    return false;
}

/// Resolve the property a mutation expression operand writes to, unwrapping
/// index-access chains (`this.grid[i][j]`). Returns null for non-`this`
/// targets.
fn mutatedPropertyName(operand: Expression) ?[]const u8 {
    var node = operand;
    while (node == .index_access) node = node.index_access.object;
    return switch (node) {
        .property_access => |pa| pa.property,
        else => null,
    };
}

const READONLY_WRITE_MSG =
    "cannot assign to readonly property outside the constructor; " ++
    "readonly properties may only be assigned in the constructor";

fn walkReadonlyWrites(
    allocator: Allocator,
    contract: ContractNode,
    stmts: []const Statement,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    for (stmts) |stmt| {
        switch (stmt) {
            .assign => |a| {
                if (a.target_is_property and isReadonlyPropertyName(contract, a.target)) {
                    // Name the offending property, as the other six tiers do
                    // ("cannot assign to readonly property 'x' ..."). A generic
                    // message is correct but makes a developer hunt for which
                    // write tripped it in a contract with several readonly
                    // properties. Allocator-owned, like the other allocPrint'd
                    // diagnostics in this file.
                    const msg = try std.fmt.allocPrint(
                        allocator,
                        "cannot assign to readonly property '{s}' outside the constructor; " ++
                            "readonly properties may only be assigned in the constructor",
                        .{a.target},
                    );
                    try errors.append(allocator, .{
                        .message = msg,
                        .severity = .@"error",
                    });
                }
                try walkExprForReadonlyMutation(allocator, contract, a.value, errors);
            },
            .const_decl => |d| try walkExprForReadonlyMutation(allocator, contract, d.value, errors),
            .let_decl => |d| {
                if (d.value) |v| try walkExprForReadonlyMutation(allocator, contract, v, errors);
            },
            .expr_stmt => |e| try walkExprForReadonlyMutation(allocator, contract, e.expr, errors),
            .assert_stmt => |a| try walkExprForReadonlyMutation(allocator, contract, a.condition, errors),
            .return_stmt => |v| {
                if (v) |e| try walkExprForReadonlyMutation(allocator, contract, e, errors);
            },
            .if_stmt => |if_s| {
                try walkExprForReadonlyMutation(allocator, contract, if_s.condition, errors);
                try walkReadonlyWrites(allocator, contract, if_s.then_body, errors);
                if (if_s.else_body) |eb| try walkReadonlyWrites(allocator, contract, eb, errors);
            },
            .for_stmt => |f| try walkReadonlyWrites(allocator, contract, f.body, errors),
        }
    }
}

/// Flag `this.p++` / `this.p--` anywhere inside an expression.
fn walkExprForReadonlyMutation(
    allocator: Allocator,
    contract: ContractNode,
    expr: Expression,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    switch (expr) {
        .increment => |inc| {
            if (mutatedPropertyName(inc.operand)) |name| {
                if (isReadonlyPropertyName(contract, name)) {
                    try errors.append(allocator, .{
                        .message = READONLY_WRITE_MSG,
                        .severity = .@"error",
                    });
                }
            }
            try walkExprForReadonlyMutation(allocator, contract, inc.operand, errors);
        },
        .decrement => |dec| {
            if (mutatedPropertyName(dec.operand)) |name| {
                if (isReadonlyPropertyName(contract, name)) {
                    try errors.append(allocator, .{
                        .message = READONLY_WRITE_MSG,
                        .severity = .@"error",
                    });
                }
            }
            try walkExprForReadonlyMutation(allocator, contract, dec.operand, errors);
        },
        .binary_op => |b| {
            try walkExprForReadonlyMutation(allocator, contract, b.left, errors);
            try walkExprForReadonlyMutation(allocator, contract, b.right, errors);
        },
        .unary_op => |u| try walkExprForReadonlyMutation(allocator, contract, u.operand, errors),
        .call => |c| {
            for (c.args) |a| try walkExprForReadonlyMutation(allocator, contract, a, errors);
        },
        .method_call => |mc| {
            for (mc.args) |a| try walkExprForReadonlyMutation(allocator, contract, a, errors);
        },
        .ternary => |t| {
            try walkExprForReadonlyMutation(allocator, contract, t.condition, errors);
            try walkExprForReadonlyMutation(allocator, contract, t.then_expr, errors);
            try walkExprForReadonlyMutation(allocator, contract, t.else_expr, errors);
        },
        .index_access => |ia| {
            try walkExprForReadonlyMutation(allocator, contract, ia.object, errors);
            try walkExprForReadonlyMutation(allocator, contract, ia.index, errors);
        },
        .array_literal => |els| {
            for (els) |e| try walkExprForReadonlyMutation(allocator, contract, e, errors);
        },
        else => {},
    }
}

/// Check if a method body ends with an asm({...}) call whose normalized
/// third positional arg (out_arity) is the integer literal 1. If/else
/// branches that both terminate in a terminal asm (or assert) also count,
/// mirroring the asserts-on-both-branches rule.
fn endsWithTerminalAsm(body: []const Statement) bool {
    if (body.len == 0) return false;
    const last = body[body.len - 1];
    return switch (last) {
        .expr_stmt => |expr| switch (expr.expr) {
            .call => |c| blk: {
                if (!std.mem.eql(u8, c.callee, "asm")) break :blk false;
                if (c.args.len != 3) break :blk false;
                break :blk switch (c.args[2]) {
                    .literal_int => |i| i == 1,
                    else => false,
                };
            },
            else => false,
        },
        .if_stmt => |if_s| {
            const then_ok = endsWithTerminalAsm(if_s.then_body) or endsWithAssert(if_s.then_body);
            const else_ok = if (if_s.else_body) |eb|
                (endsWithTerminalAsm(eb) or endsWithAssert(eb))
            else
                false;
            return then_ok and else_ok;
        },
        else => false,
    };
}

/// Walk a method body and validate every asm({...}) call:
///   - Reject any asm() outside an UnsafeSmartContract.
///   - Confirm the parser-normalised arg shape: (body, in_arity, out_arity)
///     where body is a ByteString literal with even-length hex and the
///     arities are non-negative bigint literals.
fn validateAsmUsage(
    allocator: Allocator,
    contract: ContractNode,
    method: MethodNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    for (method.body) |stmt| {
        try walkStatementForAsm(allocator, stmt, contract, errors);
    }
}

fn walkStatementForAsm(
    allocator: Allocator,
    stmt: Statement,
    contract: ContractNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    switch (stmt) {
        .expr_stmt => |e| try walkExprForAsm(allocator, e.expr, contract, errors),
        .const_decl => |cd| try walkExprForAsm(allocator, cd.value, contract, errors),
        .let_decl => |ld| {
            if (ld.value) |v| try walkExprForAsm(allocator, v, contract, errors);
        },
        .assign => |a| try walkExprForAsm(allocator, a.value, contract, errors),
        .if_stmt => |if_s| {
            try walkExprForAsm(allocator, if_s.condition, contract, errors);
            for (if_s.then_body) |s| try walkStatementForAsm(allocator, s, contract, errors);
            if (if_s.else_body) |eb| {
                for (eb) |s| try walkStatementForAsm(allocator, s, contract, errors);
            }
        },
        .for_stmt => |fs| {
            for (fs.body) |s| try walkStatementForAsm(allocator, s, contract, errors);
        },
        .assert_stmt => |a| try walkExprForAsm(allocator, a.condition, contract, errors),
        .return_stmt => |opt| {
            if (opt) |e| try walkExprForAsm(allocator, e, contract, errors);
        },
    }
}

fn walkExprForAsm(
    allocator: Allocator,
    expr: Expression,
    contract: ContractNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    switch (expr) {
        .call => |c| {
            if (std.mem.eql(u8, c.callee, "asm")) {
                try checkAsmCall(allocator, c, contract, errors);
            }
            for (c.args) |arg| try walkExprForAsm(allocator, arg, contract, errors);
        },
        .method_call => |mc| {
            for (mc.args) |arg| try walkExprForAsm(allocator, arg, contract, errors);
        },
        .binary_op => |b| {
            try walkExprForAsm(allocator, b.left, contract, errors);
            try walkExprForAsm(allocator, b.right, contract, errors);
        },
        .unary_op => |u| try walkExprForAsm(allocator, u.operand, contract, errors),
        .ternary => |t| {
            try walkExprForAsm(allocator, t.condition, contract, errors);
            try walkExprForAsm(allocator, t.then_expr, contract, errors);
            try walkExprForAsm(allocator, t.else_expr, contract, errors);
        },
        .index_access => |ia| {
            try walkExprForAsm(allocator, ia.object, contract, errors);
            try walkExprForAsm(allocator, ia.index, contract, errors);
        },
        .increment => |inc| try walkExprForAsm(allocator, inc.operand, contract, errors),
        .decrement => |dec| try walkExprForAsm(allocator, dec.operand, contract, errors),
        .array_literal => |al| {
            for (al) |e| try walkExprForAsm(allocator, e, contract, errors);
        },
        .literal_int, .literal_bigint, .literal_bool, .literal_bytes, .identifier, .property_access => {},
    }
}

fn checkAsmCall(
    allocator: Allocator,
    call: *const types.CallExpr,
    contract: ContractNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    if (contract.parent_class != .unsafe_smart_contract) {
        try errors.append(allocator, .{
            .message = "'asm' is only available in contracts extending UnsafeSmartContract. Move the call into a class that extends UnsafeSmartContract.",
            .severity = .@"error",
        });
        return;
    }

    if (call.args.len != 3) {
        try errors.append(allocator, .{
            .message = "asm() expects exactly one object-literal argument { body, in_arity?, out_arity? }",
            .severity = .@"error",
        });
        return;
    }

    // Body must be a ByteString literal with even-length hex.
    switch (call.args[0]) {
        .literal_bytes => |body| {
            if (body.len == 0) {
                try errors.append(allocator, .{
                    .message = "asm() body must be a non-empty hex string literal",
                    .severity = .@"error",
                });
            } else if (body.len % 2 != 0) {
                try errors.append(allocator, .{
                    .message = "asm() body has odd hex length; each opcode byte requires two hex characters",
                    .severity = .@"error",
                });
            } else {
                for (body) |c| {
                    const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
                    if (!is_hex) {
                        try errors.append(allocator, .{
                            .message = "asm() body contains non-hex characters; only 0-9, a-f, A-F are allowed",
                            .severity = .@"error",
                        });
                        break;
                    }
                }
            }
        },
        else => try errors.append(allocator, .{
            .message = "asm() body must be a hex string literal",
            .severity = .@"error",
        }),
    }

    // in_arity must be a non-negative integer literal.
    switch (call.args[1]) {
        .literal_int => |i| {
            if (i < 0) try errors.append(allocator, .{
                .message = "asm() in_arity must be a non-negative integer literal",
                .severity = .@"error",
            });
        },
        else => try errors.append(allocator, .{
            .message = "asm() in_arity must be a non-negative integer literal",
            .severity = .@"error",
        }),
    }

    // out_arity must be a non-negative integer literal.
    var out_arity_val: ?i64 = null;
    switch (call.args[2]) {
        .literal_int => |i| {
            if (i < 0) try errors.append(allocator, .{
                .message = "asm() out_arity must be a non-negative integer literal",
                .severity = .@"error",
            }) else {
                out_arity_val = i;
            }
        },
        else => try errors.append(allocator, .{
            .message = "asm() out_arity must be a non-negative integer literal",
            .severity = .@"error",
        }),
    }

    // Expression-form asm<T>({...}) returns a value that flows into a let
    // binding — exactly ONE stack value, so out_arity must be 1.
    if (call.asm_return_type.len > 0) {
        if (out_arity_val) |v| {
            if (v != 1) {
                try errors.append(allocator, .{
                    .message = "Expression-form asm<T>() must have out_arity 1; only a single stack value can be bound to the result variable.",
                    .severity = .@"error",
                });
            }
        }
    }
}

/// Count every `return` in `body`, at any nesting depth (arms, loop bodies).
///
/// Enforces spec/grammar.md:161 ("Public methods MUST return `void`") and :162
/// ("Public methods MUST end with an `assert(...)` call as their final
/// statement"). spec/semantics.md gives `return` no early-exit meaning at all:
/// 4.6 defines it ONLY as "the value of this method is v" (the private-helper
/// inlining semantics), while 4.7 sequences statements UNCONDITIONALLY.
///
/// Lowering it as if it were the tail of an inlined helper produced two
/// different broken scripts (NEW-012): `return;` left the enclosing branch with
/// no result, so its arm yielded OP_0 and the whole script evaluated FALSE (an
/// unspendable UTXO from source that compiled clean); `return expr;` made the
/// returned value the branch result and hence the script's final truthiness, so
/// any truthy expr spent the contract WITHOUT reaching the guarding assert
/// (fail-OPEN). The Java tier has always rejected the valued form; this brings
/// the rule to every tier and covers the bare form too.
fn countReturnStatements(body: []const Statement, out: *usize) void {
    for (body) |stmt| {
        switch (stmt) {
            .return_stmt => out.* += 1,
            .if_stmt => |s| {
                countReturnStatements(s.then_body, out);
                if (s.else_body) |eb| countReturnStatements(eb, out);
            },
            .for_stmt => |s| countReturnStatements(s.body, out),
            else => {},
        }
    }
}

/// Check if a method body ends with an assert statement (or all branches of a
/// trailing if-statement end with assert).
fn endsWithAssert(body: []const Statement) bool {
    if (body.len == 0) return false;
    const last = body[body.len - 1];

    return switch (last) {
        .assert_stmt => true,
        .expr_stmt => |expr| isAssertCall(expr.expr),
        .if_stmt => |if_s| {
            const then_ok = endsWithAssert(if_s.then_body);
            const else_ok = if (if_s.else_body) |eb| endsWithAssert(eb) else false;
            return then_ok and else_ok;
        },
        else => false,
    };
}

/// Check if an expression is a call to assert().
fn isAssertCall(expr: Expression) bool {
    return switch (expr) {
        .call => |c| std.mem.eql(u8, c.callee, "assert"),
        .method_call => |mc| std.mem.eql(u8, mc.method, "assert"),
        else => false,
    };
}

/// Validate individual statements (currently checks for-loop bounds).
fn validateStatement(
    allocator: Allocator,
    stmt: Statement,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    switch (stmt) {
        .for_stmt => |f| {
            // The parser collapses a for-loop bound to a concrete i64, but a
            // runtime bound (`i < this.x`) or an identifier bound (`i < N`)
            // is not unrollable and would otherwise silently become a
            // 0-iteration loop. Reject it here with the same diagnostic the
            // reference TS compiler emits — only genuine integer-literal bounds
            // compile. Issue #121: non-zero-start and countdown (`>`/`>=`)
            // loops with literal bounds remain supported (anf-lower binds
            // `iterVar = start + i*step` on each unrolled iteration).
            if (!f.bound_is_const) {
                try errors.append(allocator, .{
                    .message = "For loop bound must be a compile-time constant (literal or const variable)",
                    .severity = .@"error",
                });
            }
            for (f.body) |s| try validateStatement(allocator, s, errors);
        },
        .if_stmt => |if_s| {
            for (if_s.then_body) |s| try validateStatement(allocator, s, errors);
            if (if_s.else_body) |eb| {
                for (eb) |s| try validateStatement(allocator, s, errors);
            }
        },
        else => {},
    }
}

/// Warn on manual checkPreimage() or getStateScript() usage in StatefulSmartContract methods.
fn warnManualPreimageUsage(
    allocator: Allocator,
    method: MethodNode,
    warnings: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    for (method.body) |stmt| {
        try walkStatementsForPreimage(allocator, stmt, method.name, warnings);
    }
}

fn walkStatementsForPreimage(
    allocator: Allocator,
    stmt: Statement,
    method_name: []const u8,
    warnings: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    switch (stmt) {
        .expr_stmt => |expr| try walkExprForPreimage(allocator, expr.expr, method_name, warnings),
        .const_decl => |cd| try walkExprForPreimage(allocator, cd.value, method_name, warnings),
        .let_decl => |ld| {
            if (ld.value) |v| try walkExprForPreimage(allocator, v, method_name, warnings);
        },
        .assign => |a| try walkExprForPreimage(allocator, a.value, method_name, warnings),
        .if_stmt => |if_s| {
            try walkExprForPreimage(allocator, if_s.condition, method_name, warnings);
            for (if_s.then_body) |s| try walkStatementsForPreimage(allocator, s, method_name, warnings);
            if (if_s.else_body) |eb| {
                for (eb) |s| try walkStatementsForPreimage(allocator, s, method_name, warnings);
            }
        },
        .for_stmt => |fs| {
            for (fs.body) |s| try walkStatementsForPreimage(allocator, s, method_name, warnings);
        },
        .assert_stmt => |a| try walkExprForPreimage(allocator, a.condition, method_name, warnings),
        .return_stmt => |opt_expr| {
            if (opt_expr) |expr| try walkExprForPreimage(allocator, expr, method_name, warnings);
        },
    }
}

fn walkExprForPreimage(
    allocator: Allocator,
    expr: Expression,
    method_name: []const u8,
    warnings: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    switch (expr) {
        .call => |c| {
            if (std.mem.eql(u8, c.callee, "checkPreimage")) {
                try warnings.append(allocator, .{
                    .message = "StatefulSmartContract auto-injects checkPreimage(); calling it manually will cause a duplicate verification",
                    .severity = .warning,
                });
            }
            for (c.args) |arg| try walkExprForPreimage(allocator, arg, method_name, warnings);
        },
        .method_call => |mc| {
            if (std.mem.eql(u8, mc.method, "checkPreimage")) {
                try warnings.append(allocator, .{
                    .message = "StatefulSmartContract auto-injects checkPreimage(); calling it manually will cause a duplicate verification",
                    .severity = .warning,
                });
            }
            if (std.mem.eql(u8, mc.method, "getStateScript")) {
                try warnings.append(allocator, .{
                    .message = "StatefulSmartContract auto-injects state continuation; calling getStateScript() manually is redundant",
                    .severity = .warning,
                });
            }
            for (mc.args) |arg| try walkExprForPreimage(allocator, arg, method_name, warnings);
        },
        .binary_op => |b| {
            try walkExprForPreimage(allocator, b.left, method_name, warnings);
            try walkExprForPreimage(allocator, b.right, method_name, warnings);
        },
        .unary_op => |u| try walkExprForPreimage(allocator, u.operand, method_name, warnings),
        .ternary => |t| {
            try walkExprForPreimage(allocator, t.condition, method_name, warnings);
            try walkExprForPreimage(allocator, t.then_expr, method_name, warnings);
            try walkExprForPreimage(allocator, t.else_expr, method_name, warnings);
        },
        .index_access => |ia| {
            try walkExprForPreimage(allocator, ia.object, method_name, warnings);
            try walkExprForPreimage(allocator, ia.index, method_name, warnings);
        },
        .increment => |inc| try walkExprForPreimage(allocator, inc.operand, method_name, warnings),
        .decrement => |dec| try walkExprForPreimage(allocator, dec.operand, method_name, warnings),
        .literal_int, .literal_bigint, .literal_bool, .literal_bytes, .identifier,
        .property_access, .array_literal,
        => {},
    }
}

// ============================================================================
// #131: locktime soundness — extractLocktime needs an extractSequence guard
// ============================================================================

/// Sentinel maximum nSequence: a tx is FINAL (ignores locktime) at this value.
const SEQUENCE_FINAL: i128 = 0xffffffff;

/// True when `expr` is a direct call to the named intrinsic, e.g. `f(...)`. Bare
/// intrinsic calls are `.call`; a `this.foo()` method call is `.method_call`.
fn isCallToNamed(expr: Expression, name: []const u8) bool {
    return switch (expr) {
        .call => |c| std.mem.eql(u8, c.callee, name),
        else => false,
    };
}

/// True when `expr` reads the transaction locktime. Both the raw intrinsic
/// `extractLocktime(preimage)` and its ergonomic sugar `currentBlockHeight()`
/// (which the ANF pass desugars to `extractLocktime`) count — either read is
/// unsound without a sequence-finality guard.
fn isLocktimeRead(expr: Expression) bool {
    return isCallToNamed(expr, "extractLocktime") or isCallToNamed(expr, "currentBlockHeight");
}

/// True when `expr` is an int/bigint literal no greater than the finality
/// sentinel (0xffffffff), so a guard against it genuinely forces non-finality.
/// The TS reference matches a `bigint_literal`; the Zig frontend lowers small
/// bigints to `literal_int` and only oversize values to `literal_bigint`, so
/// both variants are accepted here.
fn sequenceBoundOk(expr: Expression) bool {
    return switch (expr) {
        .literal_int => |v| @as(i128, v) <= SEQUENCE_FINAL,
        .literal_bigint => |s| blk: {
            const n = std.fmt.parseInt(i128, s, 10) catch break :blk false;
            break :blk n <= SEQUENCE_FINAL;
        },
        else => false,
    };
}

/// True when `expr` is an `extractSequence(...) < <final>`-style comparison
/// (the guard that makes a locktime gate consensus-enforced). Accepts the two
/// natural spellings: `extractSequence(pre) < N` / `<= N`, and the reversed
/// `N > extractSequence(pre)` / `>= ...`. `N` must be an int/bigint literal no
/// greater than the finality sentinel.
fn isSequenceFinalityGuard(expr: Expression) bool {
    const b = switch (expr) {
        .binary_op => |bp| bp,
        else => return false,
    };
    if ((b.op == .lt or b.op == .lte) and
        isCallToNamed(b.left, "extractSequence") and sequenceBoundOk(b.right))
    {
        return true;
    }
    if ((b.op == .gt or b.op == .gte) and
        isCallToNamed(b.right, "extractSequence") and sequenceBoundOk(b.left))
    {
        return true;
    }
    return false;
}

/// Recursively scan an expression for a locktime read and/or a sequence guard,
/// setting the respective flags. Pure — no allocation.
fn scanExprForLocktime(expr: Expression, reads_locktime: *bool, has_guard: *bool) void {
    if (isLocktimeRead(expr)) reads_locktime.* = true;
    if (isSequenceFinalityGuard(expr)) has_guard.* = true;
    switch (expr) {
        .call => |c| for (c.args) |arg| scanExprForLocktime(arg, reads_locktime, has_guard),
        .method_call => |mc| for (mc.args) |arg| scanExprForLocktime(arg, reads_locktime, has_guard),
        .binary_op => |b| {
            scanExprForLocktime(b.left, reads_locktime, has_guard);
            scanExprForLocktime(b.right, reads_locktime, has_guard);
        },
        .unary_op => |u| scanExprForLocktime(u.operand, reads_locktime, has_guard),
        .ternary => |t| {
            scanExprForLocktime(t.condition, reads_locktime, has_guard);
            scanExprForLocktime(t.then_expr, reads_locktime, has_guard);
            scanExprForLocktime(t.else_expr, reads_locktime, has_guard);
        },
        .index_access => |ia| {
            scanExprForLocktime(ia.object, reads_locktime, has_guard);
            scanExprForLocktime(ia.index, reads_locktime, has_guard);
        },
        .increment => |inc| scanExprForLocktime(inc.operand, reads_locktime, has_guard),
        .decrement => |dec| scanExprForLocktime(dec.operand, reads_locktime, has_guard),
        .literal_int, .literal_bigint, .literal_bool, .literal_bytes, .identifier,
        .property_access, .array_literal,
        => {},
    }
}

/// Statement walker feeding `scanExprForLocktime`.
fn scanStmtForLocktime(stmt: Statement, reads_locktime: *bool, has_guard: *bool) void {
    switch (stmt) {
        .expr_stmt => |expr| scanExprForLocktime(expr.expr, reads_locktime, has_guard),
        .const_decl => |cd| scanExprForLocktime(cd.value, reads_locktime, has_guard),
        .let_decl => |ld| {
            if (ld.value) |v| scanExprForLocktime(v, reads_locktime, has_guard);
        },
        .assign => |a| scanExprForLocktime(a.value, reads_locktime, has_guard),
        .if_stmt => |if_s| {
            scanExprForLocktime(if_s.condition, reads_locktime, has_guard);
            for (if_s.then_body) |s| scanStmtForLocktime(s, reads_locktime, has_guard);
            if (if_s.else_body) |eb| {
                for (eb) |s| scanStmtForLocktime(s, reads_locktime, has_guard);
            }
        },
        .for_stmt => |fs| {
            for (fs.body) |s| scanStmtForLocktime(s, reads_locktime, has_guard);
        },
        .assert_stmt => |a| scanExprForLocktime(a.condition, reads_locktime, has_guard),
        .return_stmt => |opt_expr| {
            if (opt_expr) |expr| scanExprForLocktime(expr, reads_locktime, has_guard);
        },
    }
}

/// #131: warn when `method` (transitively, through the private-helper call
/// graph) reads the tx locktime but never asserts the tx is non-final. A
/// locktime gate is not consensus-enforced unless `extractSequence < 0xffffffff`
/// is also asserted — otherwise an all-final-sequence spend bypasses it.
/// Advisory (warning) only — no effect on emitted bytecode. The message is
/// allocator-owned (matches sighash_validate's allocPrint'd diagnostics).
fn warnLocktimeWithoutSequenceGuard(
    allocator: Allocator,
    contract: ContractNode,
    method: MethodNode,
    warnings: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    var reads_locktime = false;
    var has_sequence_guard = false;

    var visited = StringSet{};
    defer visited.deinit(allocator);
    try visited.put(allocator, method.name, {});

    var queue: std.ArrayListUnmanaged(MethodNode) = .empty;
    defer queue.deinit(allocator);
    try queue.append(allocator, method);

    var head: usize = 0;
    while (head < queue.items.len) : (head += 1) {
        const current = queue.items[head];
        for (current.body) |stmt| {
            scanStmtForLocktime(stmt, &reads_locktime, &has_sequence_guard);
        }
        // Follow calls into private helpers so a guard (or locktime read)
        // supplied by an inlined helper is seen by the public entry point.
        var calls = StringSet{};
        defer calls.deinit(allocator);
        for (current.body) |stmt| {
            try collectMethodCalls(allocator, stmt, &calls);
        }
        var it = calls.iterator();
        while (it.next()) |entry| {
            const callee = entry.key_ptr.*;
            if (visited.get(callee) != null) continue;
            for (contract.methods) |m| {
                if (!m.is_public and std.mem.eql(u8, m.name, callee)) {
                    try visited.put(allocator, callee, {});
                    try queue.append(allocator, m);
                    break;
                }
            }
        }
    }

    if (reads_locktime and !has_sequence_guard) {
        const msg = try std.fmt.allocPrint(
            allocator,
            "method '{s}' reads extractLocktime but does not assert extractSequence " ++
                "< 0xffffffff; a locktime gate is not consensus-enforced unless the tx " ++
                "is non-final — add assert(extractSequence(this.txPreimage) < 0xffffffffn)",
            .{method.name},
        );
        try warnings.append(allocator, .{
            .message = msg,
            .owned_message = true,
            .severity = .warning,
        });
    }
}

// ============================================================================
// Recursion detection
// ============================================================================

const StringSet = std.StringHashMapUnmanaged(void);

/// Build a call graph and check for cycles using DFS.
fn checkNoRecursion(
    allocator: Allocator,
    contract: ContractNode,
    errors: *std.ArrayListUnmanaged(CompilerDiagnostic),
) !void {
    // Build call graph: method_name -> set of called method names
    var call_graph = std.StringHashMapUnmanaged(StringSet){};
    defer {
        var it = call_graph.iterator();
        while (it.next()) |entry| {
            var set = entry.value_ptr.*;
            set.deinit(allocator);
        }
        call_graph.deinit(allocator);
    }

    var method_names = StringSet{};
    defer method_names.deinit(allocator);

    for (contract.methods) |method| {
        try method_names.put(allocator, method.name, {});

        var calls = StringSet{};
        for (method.body) |stmt| {
            try collectMethodCalls(allocator, stmt, &calls);
        }
        try call_graph.put(allocator, method.name, calls);
    }

    // Check for cycles using DFS from each method
    for (contract.methods) |method| {
        var visited = StringSet{};
        defer visited.deinit(allocator);
        var stack = StringSet{};
        defer stack.deinit(allocator);

        if (try hasCycle(allocator, method.name, &call_graph, &method_names, &visited, &stack)) {
            try errors.append(allocator, .{
                .message = "recursion detected: method calls itself directly or indirectly",
                .severity = .@"error",
            });
        }
    }
}

fn hasCycle(
    allocator: Allocator,
    name: []const u8,
    call_graph: *std.StringHashMapUnmanaged(StringSet),
    method_names: *StringSet,
    visited: *StringSet,
    stack: *StringSet,
) !bool {
    if (stack.get(name) != null) return true;
    if (visited.get(name) != null) return false;

    try visited.put(allocator, name, {});
    try stack.put(allocator, name, {});

    if (call_graph.getPtr(name)) |calls| {
        var it = calls.iterator();
        while (it.next()) |entry| {
            const callee = entry.key_ptr.*;
            if (method_names.get(callee) != null) {
                if (try hasCycle(allocator, callee, call_graph, method_names, visited, stack)) {
                    return true;
                }
            }
        }
    }

    _ = stack.remove(name);
    return false;
}

/// Collect method calls from statements.
fn collectMethodCalls(allocator: Allocator, stmt: Statement, calls: *StringSet) !void {
    switch (stmt) {
        .expr_stmt => |expr| try collectMethodCallsInExpr(allocator, expr.expr, calls),
        .const_decl => |cd| try collectMethodCallsInExpr(allocator, cd.value, calls),
        .let_decl => |ld| {
            if (ld.value) |v| try collectMethodCallsInExpr(allocator, v, calls);
        },
        .assign => |a| try collectMethodCallsInExpr(allocator, a.value, calls),
        .if_stmt => |if_s| {
            try collectMethodCallsInExpr(allocator, if_s.condition, calls);
            for (if_s.then_body) |s| try collectMethodCalls(allocator, s, calls);
            if (if_s.else_body) |eb| {
                for (eb) |s| try collectMethodCalls(allocator, s, calls);
            }
        },
        .for_stmt => |fs| {
            for (fs.body) |s| try collectMethodCalls(allocator, s, calls);
        },
        .assert_stmt => |a| try collectMethodCallsInExpr(allocator, a.condition, calls),
        .return_stmt => |opt_expr| {
            if (opt_expr) |expr| try collectMethodCallsInExpr(allocator, expr, calls);
        },
    }
}

fn collectMethodCallsInExpr(allocator: Allocator, expr: Expression, calls: *StringSet) !void {
    switch (expr) {
        .call => |c| {
            // Bare function calls that might be method references
            try calls.put(allocator, c.callee, {});
            for (c.args) |arg| try collectMethodCallsInExpr(allocator, arg, calls);
        },
        .method_call => |mc| {
            // this.methodName() calls
            if (std.mem.eql(u8, mc.object, "this")) {
                try calls.put(allocator, mc.method, {});
            }
            for (mc.args) |arg| try collectMethodCallsInExpr(allocator, arg, calls);
        },
        .binary_op => |b| {
            try collectMethodCallsInExpr(allocator, b.left, calls);
            try collectMethodCallsInExpr(allocator, b.right, calls);
        },
        .unary_op => |u| try collectMethodCallsInExpr(allocator, u.operand, calls),
        .ternary => |t| {
            try collectMethodCallsInExpr(allocator, t.condition, calls);
            try collectMethodCallsInExpr(allocator, t.then_expr, calls);
            try collectMethodCallsInExpr(allocator, t.else_expr, calls);
        },
        .index_access => |ia| {
            try collectMethodCallsInExpr(allocator, ia.object, calls);
            try collectMethodCallsInExpr(allocator, ia.index, calls);
        },
        .increment => |inc| try collectMethodCallsInExpr(allocator, inc.operand, calls),
        .decrement => |dec| try collectMethodCallsInExpr(allocator, dec.operand, calls),
        .literal_int, .literal_bigint, .literal_bool, .literal_bytes, .identifier,
        .property_access, .array_literal,
        => {},
    }
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

// -- Test helpers --

fn makeProperty(name: []const u8, type_info: RunarType, readonly: bool) PropertyNode {
    return .{ .name = name, .type_info = type_info, .readonly = readonly };
}

fn makePropertyWithInit(name: []const u8, type_info: RunarType, readonly: bool) PropertyNode {
    return .{ .name = name, .type_info = type_info, .readonly = readonly, .initializer = .{ .literal_int = 0 } };
}

/// `this.<target> = <target>` — a property initialised from the constructor
/// parameter of the same name, which is what every test contract below pairs
/// with `makeParam(target)`.
///
/// This used to build `.value = .{ .literal_int = 0 }`, an AST no frontend
/// parser produces: an assigned LITERAL is not a deploy-time argument, so the
/// property it targets ends up with neither an initializer nor a constructor
/// slot. The NEW-002 bijection check reads exactly this edge, so the fiction
/// became visible as a diagnostic on contracts the tests call valid.
fn makeAssignment(target: []const u8) types.AssignmentNode {
    return .{ .target = target, .value = .{ .identifier = target } };
}

fn makeParam(name: []const u8) types.ParamNode {
    return .{ .name = name, .type_name = "bigint" };
}

fn makeZigParam(name: []const u8) types.ParamNode {
    return .{ .name = name };
}

// -- Property validation tests --

test "valid SmartContract passes validation" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    var body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &body },
    };
    const contract = ContractNode{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    try testing.expectEqual(@as(usize, 0), result.errors.len);
    try testing.expectEqual(@as(usize, 0), result.warnings.len);
}

// NEW-012 — `return` in a PUBLIC method.
//
// spec/grammar.md:161 makes public methods void, :162 makes their trailing
// assert the spending condition, and spec/semantics.md gives `return` no
// early-exit meaning at all (4.6 defines only "the value of this method is v";
// 4.7 sequences statements unconditionally).
//
// Lowering it as if it were the tail of an inlined helper produced two broken
// scripts: `return;` left the enclosing arm with no result, so it yielded OP_0
// and the whole script evaluated FALSE — an unspendable UTXO from source that
// compiled clean; `return expr;` made the returned value the branch result and
// hence the script's final truthiness, so any truthy expr spent the contract
// WITHOUT reaching the guarding assert (fail-OPEN).
test "bare return in a public method is rejected" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{makeProperty("pk", .pub_key, true)};
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    var then_body = [_]Statement{.{ .return_stmt = null }};
    var body = [_]Statement{
        .{ .if_stmt = .{ .condition = .{ .literal_bool = true }, .then_body = &then_body } },
        .{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } },
    };
    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &body },
    };
    const contract = ContractNode{
        .name = "Guard",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var hits: usize = 0;
    for (result.errors) |e| {
        if (std.mem.indexOf(u8, e.message, "must not use `return`") != null) hits += 1;
    }
    try testing.expectEqual(@as(usize, 1), hits);
}

test "valued return in a public method is rejected" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{makeProperty("pk", .pub_key, true)};
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    var then_body = [_]Statement{.{ .return_stmt = Expression{ .literal_bool = true } }};
    var body = [_]Statement{
        .{ .if_stmt = .{ .condition = .{ .literal_bool = true }, .then_body = &then_body } },
        .{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } },
    };
    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &body },
    };
    const contract = ContractNode{
        .name = "Guard",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var hits: usize = 0;
    for (result.errors) |e| {
        if (std.mem.indexOf(u8, e.message, "must not use `return`") != null) hits += 1;
    }
    try testing.expectEqual(@as(usize, 1), hits);
}

// spec/grammar.md:168 — "Private methods may return a value." The rejection
// must not spill onto the inlined-helper form, which is how ~340 in-repo
// contracts legitimately use `return`.
test "return in a private helper is allowed" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{makeProperty("pk", .pub_key, true)};
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    var helper_body = [_]Statement{.{ .return_stmt = Expression{ .literal_bool = true } }};
    var public_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "helper", .is_public = false, .params = &.{}, .body = &helper_body },
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &public_body },
    };
    const contract = ContractNode{
        .name = "Guard",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    for (result.errors) |e| {
        try testing.expect(std.mem.indexOf(u8, e.message, "must not use `return`") == null);
    }
}

test "void property type is rejected" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("x", .void, true),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    try testing.expect(result.errors.len >= 1);
    try testing.expectEqualStrings("property type 'void' is not valid", result.errors[0].message);
}

test "SmartContract rejects mutable property" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("counter", .bigint, false),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("counter")};
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found_readonly_error = false;
    for (result.errors) |err| {
        if (std.mem.eql(u8, err.message, "property in SmartContract must be declared readonly")) {
            found_readonly_error = true;
            break;
        }
    }
    try testing.expect(found_readonly_error);
}

test "StatefulSmartContract warns on no mutable properties" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    try testing.expect(result.warnings.len >= 1);
    try testing.expectEqualStrings(
        "StatefulSmartContract has no mutable properties; consider using SmartContract instead",
        result.warnings[0].message,
    );
}

test "StatefulSmartContract rejects explicit txPreimage" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("txPreimage", .sig_hash_preimage, true),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("txPreimage")};
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "txPreimage") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

// -- Constructor validation tests --

test "constructor missing super() call reports error" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var params = [_]types.ParamNode{makeParam("pk")};
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &.{}, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "super()") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "zig constructor without super() passes when properties are assigned" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var assignments = [_]types.AssignmentNode{
        .{ .target = "pk", .value = .{ .identifier = "pk" } },
    };
    var params = [_]types.ParamNode{makeZigParam("pk")};
    var body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &body },
    };
    const contract = ContractNode{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &.{}, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validateZig(allocator, contract);
    defer freeResult(allocator, result);

    try testing.expectEqual(@as(usize, 0), result.errors.len);
}

test "zig constructor missing property assignment reports error without super() noise" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
        makeProperty("amount", .bigint, true),
    };
    var assignments = [_]types.AssignmentNode{
        .{ .target = "pk", .value = .{ .identifier = "pk" } },
    };
    var params = [_]types.ParamNode{ makeZigParam("pk"), makeZigParam("amount") };
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &.{}, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validateZig(allocator, contract);
    defer freeResult(allocator, result);

    var found_assignment_error = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "super()") != null) {
            return error.TestUnexpectedResult;
        }
        if (std.mem.eql(u8, err.message, "property must be assigned in the constructor")) {
            found_assignment_error = true;
        }
    }
    try testing.expect(found_assignment_error);
}

test "constructor missing property assignment reports error" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
        makeProperty("amount", .bigint, true),
    };
    // Only assign pk, not amount
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{ .{ .identifier = "pk" }, .{ .identifier = "amount" } };
    var params = [_]types.ParamNode{ makeParam("pk"), makeParam("amount") };
    const contract = ContractNode{
        .name = "Bad",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "property must be assigned") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "property with initializer does not require constructor assignment" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
        makePropertyWithInit("counter", .bigint, false),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    // Should have no "property must be assigned" errors (counter has initializer)
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "counter") != null and
            std.mem.indexOf(u8, err.message, "assigned") != null)
        {
            return error.TestUnexpectedResult;
        }
    }
}

// -- Method validation tests --

test "public method without assert reports error for SmartContract" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var body = [_]Statement{.{ .expr_stmt = .{ .expr = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    const contract = ContractNode{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "assert()") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "for loop with non-constant bound is rejected" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("x", .bigint, true),
    };
    // for (let i = 0; i < <runtime>; i++) {}  — bound_is_const = false marks a
    // runtime/identifier bound that the parser could not resolve to a literal.
    var loop_body = [_]Statement{};
    var body = [_]Statement{
        .{ .for_stmt = .{
            .var_name = "i",
            .init_value = 0,
            .bound = 0,
            .bound_is_const = false,
            .body = &loop_body,
        } },
        .{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } },
    };
    var methods = [_]MethodNode{
        .{ .name = "run", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    var super_args = [_]Expression{.{ .identifier = "x" }};
    var params = [_]types.ParamNode{makeParam("x")};
    const contract = ContractNode{
        .name = "LoopRuntime",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "compile-time constant") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "public method ending with assert_stmt passes" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("pk", .pub_key, true),
    };
    var body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("pk")};
    var super_args = [_]Expression{.{ .identifier = "pk" }};
    var params = [_]types.ParamNode{makeParam("pk")};
    const contract = ContractNode{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "assert()") != null) {
            return error.TestUnexpectedResult;
        }
    }
}

test "StatefulSmartContract public method without assert is OK" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("counter", .bigint, false),
    };
    var body = [_]Statement{.{ .expr_stmt = .{ .expr = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "increment", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("counter")};
    var super_args = [_]Expression{.{ .identifier = "counter" }};
    var params = [_]types.ParamNode{makeParam("counter")};
    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "assert()") != null) {
            return error.TestUnexpectedResult;
        }
    }
}

// -- Recursion detection tests --

test "direct recursion detected" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("x", .bigint, true),
    };

    // Method "foo" calls this.foo() -> direct recursion
    var call_expr = types.MethodCall{ .object = "this", .method = "foo", .args = &.{} };
    var body = [_]Statement{.{ .expr_stmt = .{ .expr = .{ .method_call = &call_expr } } }};
    var assert_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "foo", .is_public = false, .params = &.{}, .body = &body },
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &assert_body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    var super_args = [_]Expression{.{ .identifier = "x" }};
    var params = [_]types.ParamNode{makeParam("x")};
    const contract = ContractNode{
        .name = "Recursive",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "recursion detected") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "indirect recursion detected" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("x", .bigint, true),
    };

    // Method "a" calls this.b(), method "b" calls this.a() -> indirect recursion
    var call_b = types.MethodCall{ .object = "this", .method = "b", .args = &.{} };
    var body_a = [_]Statement{.{ .expr_stmt = .{ .expr = .{ .method_call = &call_b } } }};
    var call_a = types.MethodCall{ .object = "this", .method = "a", .args = &.{} };
    var body_b = [_]Statement{.{ .expr_stmt = .{ .expr = .{ .method_call = &call_a } } }};
    var assert_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "a", .is_public = false, .params = &.{}, .body = &body_a },
        .{ .name = "b", .is_public = false, .params = &.{}, .body = &body_b },
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &assert_body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    var super_args = [_]Expression{.{ .identifier = "x" }};
    var params = [_]types.ParamNode{makeParam("x")};
    const contract = ContractNode{
        .name = "Recursive",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var recursion_count: usize = 0;
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "recursion detected") != null) {
            recursion_count += 1;
        }
    }
    // Both "a" and "b" should report recursion
    try testing.expect(recursion_count >= 2);
}

test "no recursion in acyclic call graph" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("x", .bigint, true),
    };

    // Method "a" calls this.b(), method "b" does not call anything -> no cycle
    var call_b = types.MethodCall{ .object = "this", .method = "b", .args = &.{} };
    var body_a = [_]Statement{.{ .expr_stmt = .{ .expr = .{ .method_call = &call_b } } }};
    var body_b = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var assert_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "a", .is_public = false, .params = &.{}, .body = &body_a },
        .{ .name = "b", .is_public = false, .params = &.{}, .body = &body_b },
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &assert_body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    var super_args = [_]Expression{.{ .identifier = "x" }};
    var params = [_]types.ParamNode{makeParam("x")};
    const contract = ContractNode{
        .name = "NoRecurse",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, "recursion") != null) {
            return error.TestUnexpectedResult;
        }
    }
}

// -- Preimage warning tests --

test "StatefulSmartContract warns on manual checkPreimage call" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("counter", .bigint, false),
    };
    var check_call = types.CallExpr{ .callee = "checkPreimage", .args = &.{} };
    var body = [_]Statement{.{ .expr_stmt = .{ .expr = .{ .call = &check_call } } }};
    var methods = [_]MethodNode{
        .{ .name = "increment", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("counter")};
    var super_args = [_]Expression{.{ .identifier = "counter" }};
    var params = [_]types.ParamNode{makeParam("counter")};
    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.warnings) |w| {
        if (std.mem.indexOf(u8, w.message, "checkPreimage") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "StatefulSmartContract warns on manual getStateScript call" {
    const allocator = testing.allocator;
    const props = [_]PropertyNode{
        makeProperty("counter", .bigint, false),
    };
    var mc = types.MethodCall{ .object = "this", .method = "getStateScript", .args = &.{} };
    var body = [_]Statement{.{ .expr_stmt = .{ .expr = .{ .method_call = &mc } } }};
    var methods = [_]MethodNode{
        .{ .name = "increment", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("counter")};
    var super_args = [_]Expression{.{ .identifier = "counter" }};
    var params = [_]types.ParamNode{makeParam("counter")};
    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    var found = false;
    for (result.warnings) |w| {
        if (std.mem.indexOf(u8, w.message, "getStateScript") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

// -- Edge cases --

test "empty contract with no properties or methods" {
    const allocator = testing.allocator;
    const contract = ContractNode{
        .name = "Empty",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);

    // A contract with no methods has no public spending entry point (#126),
    // which is now a validation error — the only one for an otherwise-empty contract.
    try testing.expectEqual(@as(usize, 1), result.errors.len);
    try testing.expect(hasErrorContaining(result, "no public methods"));
    try testing.expectEqual(@as(usize, 0), result.warnings.len);
}

test "endsWithAssert detects assert in both if branches" {
    // if-stmt where both branches end with assert -> OK
    var then_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var else_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    const body = [_]Statement{.{ .if_stmt = .{
        .condition = .{ .literal_bool = true },
        .then_body = &then_body,
        .else_body = &else_body,
    } }};
    try testing.expect(endsWithAssert(&body));
}

test "endsWithAssert rejects if with missing else assert" {
    var then_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    const body = [_]Statement{.{ .if_stmt = .{
        .condition = .{ .literal_bool = true },
        .then_body = &then_body,
        .else_body = null,
    } }};
    try testing.expect(!endsWithAssert(&body));
}

test "endsWithAssert on empty body returns false" {
    try testing.expect(!endsWithAssert(&.{}));
}

// -- #126: contract must have at least one public method --

fn hasErrorContaining(result: ValidationResult, needle: []const u8) bool {
    for (result.errors) |err| {
        if (std.mem.indexOf(u8, err.message, needle) != null) return true;
    }
    return false;
}

test "no public methods reports error" {
    const allocator = testing.allocator;
    var props = [_]PropertyNode{makeProperty("x", .bigint, true)};
    var assert_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "helper", .is_public = false, .params = &.{}, .body = &assert_body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    var super_args = [_]Expression{.{ .identifier = "x" }};
    var params = [_]types.ParamNode{makeParam("x")};
    const contract = ContractNode{
        .name = "Locked",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);
    try testing.expect(hasErrorContaining(result, "no public methods"));
}

test "contract with no methods at all reports no-public-methods error" {
    const allocator = testing.allocator;
    var props = [_]PropertyNode{makeProperty("x", .bigint, true)};
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    var super_args = [_]Expression{.{ .identifier = "x" }};
    var params = [_]types.ParamNode{makeParam("x")};
    const contract = ContractNode{
        .name = "Empty",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &.{},
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);
    try testing.expect(hasErrorContaining(result, "no public methods"));
}

test "contract with a public method does not report no-public-methods error" {
    const allocator = testing.allocator;
    var props = [_]PropertyNode{makeProperty("x", .bigint, true)};
    var assert_body = [_]Statement{.{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } }};
    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &assert_body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    var super_args = [_]Expression{.{ .identifier = "x" }};
    var params = [_]types.ParamNode{makeParam("x")};
    const contract = ContractNode{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);
    try testing.expect(!hasErrorContaining(result, "no public methods"));
}

// -- #121: non-zero-start and countdown loops are supported (no longer rejected) --

/// Validate a stateless contract with a single public method `m` whose body is
/// the given for-loop followed by a terminal assert. Returns whether any error
/// message contains `needle`.
fn validateLoopHasError(allocator: Allocator, for_stmt: types.ForStmt, needle: []const u8) !bool {
    var props = [_]PropertyNode{makeProperty("x", .bigint, true)};
    var body = [_]Statement{
        .{ .for_stmt = for_stmt },
        .{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } },
    };
    var methods = [_]MethodNode{
        .{ .name = "m", .is_public = true, .params = &.{}, .body = &body },
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("x")};
    var super_args = [_]Expression{.{ .identifier = "x" }};
    var params = [_]types.ParamNode{makeParam("x")};
    const contract = ContractNode{
        .name = "C",
        .parent_class = .smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeResult(allocator, result);
    return hasErrorContaining(result, needle);
}

test "for loop with non-zero start is accepted (#121)" {
    // for (let i = 1; i <= 3; i++)
    const for_stmt = types.ForStmt{ .var_name = "i", .init_value = 1, .bound = 3, .inclusive = true, .body = &.{} };
    try testing.expect(!try validateLoopHasError(testing.allocator, for_stmt, "must start at 0"));
}

test "countdown for loop is accepted (#121)" {
    // for (let i = 3; i > 0; i--)
    const for_stmt = types.ForStmt{ .var_name = "i", .init_value = 3, .bound = 0, .descending = true, .body = &.{} };
    try testing.expect(!try validateLoopHasError(testing.allocator, for_stmt, "countdown"));
}

test "zero-start counting-up for loop is accepted" {
    // for (let i = 0; i <= 3; i++)
    const for_stmt = types.ForStmt{ .var_name = "i", .init_value = 0, .bound = 4, .body = &.{} };
    try testing.expect(!try validateLoopHasError(testing.allocator, for_stmt, "must start at 0"));
    try testing.expect(!try validateLoopHasError(testing.allocator, for_stmt, "countdown"));
}

// -- #131 (H2): extractLocktime without extractSequence guard ----------------

const LOCKTIME_NEEDLE = "does not assert extractSequence";

fn locktimeWarning(result: ValidationResult) ?CompilerDiagnostic {
    for (result.warnings) |w| {
        if (std.mem.indexOf(u8, w.message, LOCKTIME_NEEDLE) != null) return w;
    }
    return null;
}

fn hasLocktimeWarning(result: ValidationResult) bool {
    return locktimeWarning(result) != null;
}

/// Retained for readability at the locktime test call sites: `freeResult` now
/// frees every allocator-owned message via `owned_message`, so the old
/// free-by-substring pass would be a double free.
fn freeLocktimeResult(allocator: Allocator, result: ValidationResult) void {
    freeResult(allocator, result);
}

test "H2: warns when a public method reads extractLocktime without a sequence guard" {
    const allocator = testing.allocator;

    // assert(extractLocktime(this.txPreimage) >= this.deadline)
    var lt_args = [_]Expression{.{ .property_access = .{ .object = "this", .property = "txPreimage" } }};
    var lt_call = types.CallExpr{ .callee = "extractLocktime", .args = &lt_args };
    var lt_cmp = types.BinaryOp{
        .op = .gte,
        .left = .{ .call = &lt_call },
        .right = .{ .property_access = .{ .object = "this", .property = "deadline" } },
    };
    var inc = types.IncrementExpr{ .operand = .{ .property_access = .{ .object = "this", .property = "count" } }, .prefix = false };
    var body = [_]Statement{
        .{ .assert_stmt = .{ .condition = .{ .binary_op = &lt_cmp } } },
        .{ .expr_stmt = .{ .expr = .{ .increment = &inc } } },
    };
    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &body },
    };
    const props = [_]PropertyNode{
        makeProperty("count", .bigint, false),
        makeProperty("deadline", .bigint, true),
    };
    var assignments = [_]types.AssignmentNode{ makeAssignment("count"), makeAssignment("deadline") };
    var super_args = [_]Expression{ .{ .identifier = "count" }, .{ .identifier = "deadline" } };
    var params = [_]types.ParamNode{ makeParam("count"), makeParam("deadline") };
    const contract = ContractNode{
        .name = "TimeLock",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeLocktimeResult(allocator, result);

    try testing.expect(hasLocktimeWarning(result));
    const w = locktimeWarning(result).?;
    try testing.expect(w.severity == .warning);
    try testing.expect(std.mem.indexOf(u8, w.message, "unlock") != null);
    try testing.expect(std.mem.indexOf(u8, w.message, "0xffffffff") != null);
}

test "H2: does NOT warn when the method also asserts extractSequence < final" {
    const allocator = testing.allocator;

    // assert(extractSequence(this.txPreimage) < 0xffffffffn)
    var seq_args = [_]Expression{.{ .property_access = .{ .object = "this", .property = "txPreimage" } }};
    var seq_call = types.CallExpr{ .callee = "extractSequence", .args = &seq_args };
    var seq_cmp = types.BinaryOp{ .op = .lt, .left = .{ .call = &seq_call }, .right = .{ .literal_int = 0xffffffff } };
    // assert(extractLocktime(this.txPreimage) >= this.deadline)
    var lt_args = [_]Expression{.{ .property_access = .{ .object = "this", .property = "txPreimage" } }};
    var lt_call = types.CallExpr{ .callee = "extractLocktime", .args = &lt_args };
    var lt_cmp = types.BinaryOp{
        .op = .gte,
        .left = .{ .call = &lt_call },
        .right = .{ .property_access = .{ .object = "this", .property = "deadline" } },
    };
    var inc = types.IncrementExpr{ .operand = .{ .property_access = .{ .object = "this", .property = "count" } }, .prefix = false };
    var body = [_]Statement{
        .{ .assert_stmt = .{ .condition = .{ .binary_op = &seq_cmp } } },
        .{ .assert_stmt = .{ .condition = .{ .binary_op = &lt_cmp } } },
        .{ .expr_stmt = .{ .expr = .{ .increment = &inc } } },
    };
    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &body },
    };
    const props = [_]PropertyNode{
        makeProperty("count", .bigint, false),
        makeProperty("deadline", .bigint, true),
    };
    var assignments = [_]types.AssignmentNode{ makeAssignment("count"), makeAssignment("deadline") };
    var super_args = [_]Expression{ .{ .identifier = "count" }, .{ .identifier = "deadline" } };
    var params = [_]types.ParamNode{ makeParam("count"), makeParam("deadline") };
    const contract = ContractNode{
        .name = "TimeLock",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeLocktimeResult(allocator, result);

    try testing.expect(!hasLocktimeWarning(result));
}

test "H2: does NOT warn for a method that never reads extractLocktime" {
    const allocator = testing.allocator;

    var inc = types.IncrementExpr{ .operand = .{ .property_access = .{ .object = "this", .property = "count" } }, .prefix = false };
    var body = [_]Statement{
        .{ .expr_stmt = .{ .expr = .{ .increment = &inc } } },
    };
    var methods = [_]MethodNode{
        .{ .name = "increment", .is_public = true, .params = &.{}, .body = &body },
    };
    const props = [_]PropertyNode{
        makeProperty("count", .bigint, false),
    };
    var assignments = [_]types.AssignmentNode{makeAssignment("count")};
    var super_args = [_]Expression{.{ .identifier = "count" }};
    var params = [_]types.ParamNode{makeParam("count")};
    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeLocktimeResult(allocator, result);

    try testing.expect(!hasLocktimeWarning(result));
}

test "H2: sees a sequence guard supplied transitively through a private helper" {
    const allocator = testing.allocator;

    // private requireNonFinal(): assert(extractSequence(this.txPreimage) < 0xffffffffn)
    var seq_args = [_]Expression{.{ .property_access = .{ .object = "this", .property = "txPreimage" } }};
    var seq_call = types.CallExpr{ .callee = "extractSequence", .args = &seq_args };
    var seq_cmp = types.BinaryOp{ .op = .lt, .left = .{ .call = &seq_call }, .right = .{ .literal_int = 0xffffffff } };
    var req_body = [_]Statement{
        .{ .assert_stmt = .{ .condition = .{ .binary_op = &seq_cmp } } },
    };

    // public unlock(): this.requireNonFinal(); assert(extractLocktime(this.txPreimage) >= this.deadline); this.count++
    var req_call = types.MethodCall{ .object = "this", .method = "requireNonFinal", .args = &.{} };
    var lt_args = [_]Expression{.{ .property_access = .{ .object = "this", .property = "txPreimage" } }};
    var lt_call = types.CallExpr{ .callee = "extractLocktime", .args = &lt_args };
    var lt_cmp = types.BinaryOp{
        .op = .gte,
        .left = .{ .call = &lt_call },
        .right = .{ .property_access = .{ .object = "this", .property = "deadline" } },
    };
    var inc = types.IncrementExpr{ .operand = .{ .property_access = .{ .object = "this", .property = "count" } }, .prefix = false };
    var unlock_body = [_]Statement{
        .{ .expr_stmt = .{ .expr = .{ .method_call = &req_call } } },
        .{ .assert_stmt = .{ .condition = .{ .binary_op = &lt_cmp } } },
        .{ .expr_stmt = .{ .expr = .{ .increment = &inc } } },
    };

    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &unlock_body },
        .{ .name = "requireNonFinal", .is_public = false, .params = &.{}, .body = &req_body },
    };
    const props = [_]PropertyNode{
        makeProperty("count", .bigint, false),
        makeProperty("deadline", .bigint, true),
    };
    var assignments = [_]types.AssignmentNode{ makeAssignment("count"), makeAssignment("deadline") };
    var super_args = [_]Expression{ .{ .identifier = "count" }, .{ .identifier = "deadline" } };
    var params = [_]types.ParamNode{ makeParam("count"), makeParam("deadline") };
    const contract = ContractNode{
        .name = "TimeLock",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeLocktimeResult(allocator, result);

    try testing.expect(!hasLocktimeWarning(result));
}

test "H2: warns when the locktime read is in a private helper but no sequence guard exists" {
    const allocator = testing.allocator;

    // private checkDeadline(): assert(extractLocktime(this.txPreimage) >= this.deadline)
    var lt_args = [_]Expression{.{ .property_access = .{ .object = "this", .property = "txPreimage" } }};
    var lt_call = types.CallExpr{ .callee = "extractLocktime", .args = &lt_args };
    var lt_cmp = types.BinaryOp{
        .op = .gte,
        .left = .{ .call = &lt_call },
        .right = .{ .property_access = .{ .object = "this", .property = "deadline" } },
    };
    var check_body = [_]Statement{
        .{ .assert_stmt = .{ .condition = .{ .binary_op = &lt_cmp } } },
    };

    // public unlock(): this.checkDeadline(); this.count++
    var check_call = types.MethodCall{ .object = "this", .method = "checkDeadline", .args = &.{} };
    var inc = types.IncrementExpr{ .operand = .{ .property_access = .{ .object = "this", .property = "count" } }, .prefix = false };
    var unlock_body = [_]Statement{
        .{ .expr_stmt = .{ .expr = .{ .method_call = &check_call } } },
        .{ .expr_stmt = .{ .expr = .{ .increment = &inc } } },
    };

    var methods = [_]MethodNode{
        .{ .name = "unlock", .is_public = true, .params = &.{}, .body = &unlock_body },
        .{ .name = "checkDeadline", .is_public = false, .params = &.{}, .body = &check_body },
    };
    const props = [_]PropertyNode{
        makeProperty("count", .bigint, false),
        makeProperty("deadline", .bigint, true),
    };
    var assignments = [_]types.AssignmentNode{ makeAssignment("count"), makeAssignment("deadline") };
    var super_args = [_]Expression{ .{ .identifier = "count" }, .{ .identifier = "deadline" } };
    var params = [_]types.ParamNode{ makeParam("count"), makeParam("deadline") };
    const contract = ContractNode{
        .name = "TimeLock",
        .parent_class = .stateful_smart_contract,
        .properties = @constCast(&props),
        .constructor = .{ .params = &params, .super_args = &super_args, .assignments = &assignments },
        .methods = &methods,
    };
    const result = try validate(allocator, contract);
    defer freeLocktimeResult(allocator, result);

    try testing.expect(hasLocktimeWarning(result));
    const w = locktimeWarning(result).?;
    // The warning names the public entry point, not the helper.
    try testing.expect(std.mem.indexOf(u8, w.message, "unlock") != null);
}
