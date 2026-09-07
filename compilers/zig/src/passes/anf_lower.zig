//! Pass 4: ANF Lower -- transforms a ContractNode (AST) into an ANFProgram (IR).
//!
//! Every subexpression becomes a named temporary binding (t0, t1, t2...).
//! This is A-Normal Form: all intermediate values are explicitly named.
//!
//! Example:
//!   hash160(pubKey) === this.pubKeyHash
//! becomes:
//!   t0 = load_param("pubKey")
//!   t1 = call("hash160", [t0])
//!   t2 = load_prop("pubKeyHash")
//!   t3 = bin_op("===", t1, t2, result_type="bytes")
//!
//! Stateful contracts get automatic preimage checking, state deserialization,
//! and output hash verification injected into public methods.

const std = @import("std");
const types = @import("../ir/types.zig");
const sighash_directive = @import("../frontend/sighash_directive.zig");

const Allocator = std.mem.Allocator;

// IR types used throughout
const ANFProgram = types.ANFProgram;
const ANFProperty = types.ANFProperty;
const ANFMethod = types.ANFMethod;
const ANFBinding = types.ANFBinding;
const ANFValue = types.ANFValue;
const ParamNode = types.ParamNode;
const ContractNode = types.ContractNode;
const ConstructorNode = types.ConstructorNode;
const MethodNode = types.MethodNode;
const PropertyNode = types.PropertyNode;
const Expression = types.Expression;
const Statement = types.Statement;
const ConstValue = types.ConstValue;
const RunarType = types.RunarType;
const BinOperator = types.BinOperator;
const UnaryOperator = types.UnaryOperator;
const ParentClass = types.ParentClass;

// ============================================================================
// Public API
// ============================================================================

pub const LowerError = error{
    OutOfMemory,
    UnsupportedExpression,
    UnsupportedStatement,
    /// A conditional declares outputs AND leaves something else the parent
    /// scope can still observe — two or more merged locals, a binding after the
    /// arm's output, a property write, or a rebound local read after the `if`.
    /// The arms' single value is already the output concat the continuation
    /// hash consumes, so the extra result has nowhere to go. Refused rather
    /// than emitting an unspendable script. See `branchOutputRejectionReason`.
    UnrepresentableBranchOutputs,
    /// A MUTABLE bigint property is initialised to a magnitude the fixed
    /// 8-byte sign-magnitude state word (`num2bin-le8`) cannot hold. Refused
    /// rather than emitting a script that deploys and can never be spent. See
    /// `checkStateBigintMagnitude`.
    UnrepresentableStateBigint,
    /// A local variable shares a contract property's name and a conditional
    /// assigns BOTH. The branch's declared result slots are identified by name,
    /// so the two cannot be told apart: both entries take the property path and
    /// the local's value is silently replaced by the property's, with the
    /// layout assertion satisfied by coincidence. Refused rather than
    /// miscompiled.
    ShadowedResultName,
};

/// Name set used for the "what does the code after this statement still read"
/// liveness question `branchOutputRejectionReason` asks.
const NameSet = std.StringHashMapUnmanaged(void);

/// Shared empty read-set, so the common call sites allocate nothing.
const EMPTY_NAME_SET = NameSet{};

/// Optional out-parameter carrying the human-readable detail behind a
/// `LowerError` whose name alone is not actionable — which locals collided,
/// what to move where. Zig errors carry no payload, and pass 5 only ever
/// `std.log.warn`s its equivalent detail (see `SilentOpZeroRefused` in
/// stack_lower.zig), which drops it on the floor for library callers. Handing
/// the text back lets `compiler_api.compileSource` and the CLI print the same
/// diagnostic the other six tiers do.
///
/// `message` is allocated with the allocator passed to `lowerToANFWithDiagnostic`,
/// so it lives exactly as long as the rest of the lowering output.
pub const LowerDiagnostic = struct {
    message: ?[]const u8 = null,
};

/// Lower a type-checked ContractNode AST into an ANFProgram IR.
pub fn lowerToANF(allocator: Allocator, contract: ContractNode) LowerError!ANFProgram {
    return lowerToANFWithDiagnostic(allocator, contract, null);
}

/// Lower a type-checked ContractNode AST into an ANFProgram IR, recording the
/// detail behind any refusal in `diag` (see `LowerDiagnostic`). Pass `null` for
/// the plain `lowerToANF` behaviour.
pub fn lowerToANFWithDiagnostic(
    allocator: Allocator,
    contract: ContractNode,
    diag: ?*LowerDiagnostic,
) LowerError!ANFProgram {
    const properties = try lowerPropertiesWithDiagnostic(allocator, contract, diag);
    const methods = try lowerMethods(allocator, contract, diag);

    // Post-pass: lift update_prop from if-else branches into flat conditionals.
    // This prevents phantom stack entries in stack lowering for patterns like
    // position dispatch (different properties updated in different branches).
    // Mirrors the TS reference compiler's liftBranchUpdateProps
    // (packages/runar-compiler/src/passes/04-anf-lower.ts).
    for (methods) |*m| {
        const old_bindings = m.bindings;
        const lifted = try liftBranchUpdateProps(allocator, old_bindings);
        // Release the outer slice from `lowerMethods`. Inner ANFBinding entries
        // that survived (those that did not match the lift pattern) are
        // copied by value into `lifted`, so the strings/sub-slices they
        // reference remain valid and are NOT freed here.
        if (old_bindings.len > 0) allocator.free(old_bindings);
        m.bindings = lifted;
        m.body = lifted;
    }

    return ANFProgram{
        .contract_name = contract.name,
        .parent_class = contract.parent_class,
        .properties = properties,
        .methods = methods,
    };
}

// ============================================================================
// Byte-type detection
// ============================================================================

fn isByteType(t: RunarType) bool {
    return switch (t) {
        .byte_string, .pub_key, .sig, .sha256, .ripemd160, .addr,
        .sig_hash_preimage, .rabin_sig, .rabin_pub_key, .point,
        .p256_point, .p384_point => true,
        else => false,
    };
}

fn isByteReturningFunction(name: []const u8) bool {
    const funcs = std.StaticStringMap(void).initComptime(.{
        .{ "sha256", {} },       .{ "ripemd160", {} },    .{ "hash160", {} },
        .{ "hash256", {} },      .{ "cat", {} },          .{ "substr", {} },
        .{ "num2bin", {} },      .{ "reverseBytes", {} }, .{ "left", {} },
        .{ "right", {} },        .{ "int2str", {} },      .{ "toByteString", {} },
        .{ "pack", {} },         .{ "ecAdd", {} },        .{ "ecMul", {} },
        .{ "ecMulGen", {} },     .{ "ecNegate", {} },     .{ "ecMakePoint", {} },
        .{ "ecEncodeCompressed", {} },
        .{ "blake3Compress", {} }, .{ "blake3Hash", {} },
        .{ "p256Add", {} },      .{ "p256Mul", {} },      .{ "p256MulGen", {} },
        .{ "p256Negate", {} },   .{ "p256EncodeCompressed", {} },
        .{ "p384Add", {} },      .{ "p384Mul", {} },      .{ "p384MulGen", {} },
        .{ "p384Negate", {} },   .{ "p384EncodeCompressed", {} },
    });
    return funcs.get(name) != null;
}

/// Check if an expression is known to produce byte-typed values.
fn isByteTypedExpr(expr: Expression, ctx: *const LowerCtx) bool {
    switch (expr) {
        .literal_bytes => return true,
        .identifier => |name| {
            // Check property types
            for (ctx.contract.properties) |p| {
                if (std.mem.eql(u8, p.name, name) and isByteType(p.type_info)) return true;
            }
            // Check method-scoped byte-typed names. `local_byte_vars` is
            // populated once per method/constructor (in `lowerMethods` /
            // `lowerStatefulPublicMethod`) with the CURRENT method's params
            // (and auto-injected continuation params) plus byte-typed locals,
            // and is shared into if/else/loop sub-contexts via `subContext`.
            // Restricting the param-type lookup to this map (instead of walking
            // ALL methods' params) fixes issue #34: a param name shared across
            // methods (e.g. one method's `x` colliding with another method's
            // `x: ByteString`) no longer poisons byte-type analysis, so
            // `1n + x` emits OP_ADD instead of OP_CAT. Mirrors the TS reference
            // `getParamType` reading only `methodParamTypes`
            // (packages/runar-compiler/src/passes/04-anf-lower.ts).
            if (ctx.local_byte_vars.get(name) != null) return true;
            return false;
        },
        .property_access => |pa| {
            for (ctx.contract.properties) |p| {
                if (std.mem.eql(u8, p.name, pa.property) and isByteType(p.type_info)) return true;
            }
            return false;
        },
        .call => |c| {
            // Expression-form asm<ByteString>({...}) yields a byte value.
            if (std.mem.eql(u8, c.callee, "asm")) {
                return std.mem.eql(u8, c.asm_return_type, "ByteString");
            }
            if (isByteReturningFunction(c.callee)) return true;
            if (c.callee.len >= 7 and std.mem.startsWith(u8, c.callee, "extract")) return true;
            return false;
        },
        .method_call => |mc| {
            if (std.mem.eql(u8, mc.object, "this") or std.mem.eql(u8, mc.object, "self")) {
                for (ctx.contract.properties) |p| {
                    if (std.mem.eql(u8, p.name, mc.method) and isByteType(p.type_info)) return true;
                }
            }
            return false;
        },
        else => return false,
    }
}

// ============================================================================
// Properties
// ============================================================================

fn lowerProperties(allocator: Allocator, contract: ContractNode) LowerError![]ANFProperty {
    return lowerPropertiesWithDiagnostic(allocator, contract, null);
}

/// Magnitude a bigint state field gets: `num2bin-le8` is a fixed 8-byte
/// little-endian SIGN-MAGNITUDE word, so bytes 0..6 plus the low 7 bits of
/// byte 7 carry the magnitude and 0x80 of byte 7 carries the sign.
const STATE_BIGINT_MAGNITUDE_LIMIT: i128 = @as(i128, 1) << 63;

/// Reject a MUTABLE bigint property initialised beyond the 8-byte state word.
///
/// The state section writes every bigint field with OP_NUM2BIN 8, which cannot
/// represent a magnitude of 2^63 or more. Nothing used to check: the compiler
/// stamped `encoding: "num2bin-le8"` on the field and carried the initializer
/// verbatim, the SDK wrote the low 8 bytes of it into the deployed state
/// section, and the covenant then rebuilt the continuation with its own
/// OP_NUM2BIN 8 — which produces different bytes — so hash256(outputs) never
/// matched and the UTXO was permanently unspendable. It deployed cleanly, with
/// no diagnostic at compile time or deploy time.
///
/// This catches the statically-known half. Values that only exist at call time
/// are stopped by the SDK serializer (packages/runar-zig/src/sdk/state.zig).
///
/// READONLY properties are deliberately exempt: they are baked into the
/// locking script as script-number pushes, never into the state section, and
/// BSV script numbers are arbitrary-precision after Genesis.
fn checkStateBigintMagnitude(
    allocator: Allocator,
    prop: ANFProperty,
    diag: ?*LowerDiagnostic,
) LowerError!void {
    if (prop.readonly) return;
    if (!std.mem.eql(u8, prop.type_name, "bigint") and !std.mem.eql(u8, prop.type_name, "int")) return;
    const value = prop.initial_value orelse return;

    var text: []const u8 = undefined;
    var owned = false;
    switch (value) {
        .integer => |v| {
            if (v > -STATE_BIGINT_MAGNITUDE_LIMIT and v < STATE_BIGINT_MAGNITUDE_LIMIT) return;
            text = try std.fmt.allocPrint(allocator, "{d}", .{v});
            owned = true;
        },
        // `big_integer` exists precisely for literals that overflow i128, so
        // every one of them is far past 2^63.
        .big_integer => |t| text = t,
        else => return,
    }
    defer if (owned) allocator.free(text);

    if (diag) |sink| {
        sink.message = std.fmt.allocPrint(
            allocator,
            "Cannot compile state property '{s}' initialised to {s}: it does not " ++
                "fit the fixed 8-byte sign-magnitude state word (magnitude must be " ++
                "< 2^63). Reduce the value, or make the property readonly if it is " ++
                "a constant rather than state.",
            .{ prop.name, text },
        ) catch null;
    }
    return LowerError.UnrepresentableStateBigint;
}

fn isConstructorParam(contract: ContractNode, name: []const u8) bool {
    for (contract.constructor.params) |p| {
        if (std.mem.eql(u8, p.name, name)) return true;
    }
    return false;
}

/// True when the constructor gives `prop_name` its value from exactly one
/// constructor PARAMETER, and that parameter feeds no other property.
///
/// Such a property gets its value from the deploy-time argument, so any
/// initializer on it is a default the argument overrides — baking the default
/// into the artifact would silently discard the argument (NEW-001). The
/// property must instead stay in the constructor slot list so the SDK writes
/// the argument.
///
/// Deliberately narrow in three ways.
///
///  1. Only a BARE parameter reference counts. `.a = 5` assigns a literal, not
///     an argument, and keeps its initializer.
///  2. The property<->parameter mapping must be ONE-TO-ONE. The artifact model
///     is positional, so a parameter feeding two properties has no
///     representation — that shape is already undeployable today when written
///     without initializers, and belongs to NEW-002.
///  3. A property assigned more than once in the constructor is skipped, for
///     the same reason.
fn constructorAssignsUniquely(contract: ContractNode, prop_name: []const u8) bool {
    var param: ?[]const u8 = null;
    var assign_count: usize = 0;

    for (contract.constructor.assignments) |a| {
        if (!std.mem.eql(u8, a.target, prop_name)) continue;
        assign_count += 1;
        switch (a.value) {
            .identifier => |name| {
                if (!isConstructorParam(contract, name)) return false;
                param = name;
            },
            else => return false,
        }
    }
    if (assign_count != 1) return false;
    const p = param orelse return false;

    var feeds: usize = 0;
    for (contract.constructor.assignments) |a| {
        switch (a.value) {
            .identifier => |name| {
                if (std.mem.eql(u8, name, p)) feeds += 1;
            },
            else => {},
        }
    }
    return feeds == 1;
}

fn lowerPropertiesWithDiagnostic(
    allocator: Allocator,
    contract: ContractNode,
    diag: ?*LowerDiagnostic,
) LowerError![]ANFProperty {
    if (contract.properties.len == 0) return &.{};

    var result: std.ArrayListUnmanaged(ANFProperty) = .empty;
    for (contract.properties) |prop| {
        var anf_prop = ANFProperty{
            .name = prop.name,
            .type_name = types.runarTypeToString(prop.type_info),
            .type_info = prop.type_info,
            .readonly = prop.readonly,
            .synthetic_array_chain = prop.synthetic_array_chain,
        };
        // Only emit initialValue for properties that have defaults AND do NOT
        // take their value from a constructor argument. See
        // `constructorAssignsUniquely`.
        if (prop.initializer) |init_expr| {
            if (!constructorAssignsUniquely(contract, prop.name)) {
                anf_prop.initial_value = extractLiteralValue(init_expr);
            }
        }
        try checkStateBigintMagnitude(allocator, anf_prop, diag);
        try result.append(allocator, anf_prop);
    }
    return try result.toOwnedSlice(allocator);
}

fn extractLiteralValue(expr: Expression) ?ConstValue {
    switch (expr) {
        .literal_int => |v| return .{ .integer = v },
        .literal_bigint => |s| return .{ .big_integer = s },
        .literal_bool => |v| return .{ .boolean = v },
        .literal_bytes => |v| return .{ .string = v },
        .unary_op => |uop| {
            if (uop.op == .negate) {
                switch (uop.operand) {
                    .literal_int => |v| return .{ .integer = -v },
                    // Negate of a literal_bigint is preserved as a
                    // prefixed-`-` decimal so the value remains a single
                    // canonical text token through ANF / JSON / codegen.
                    // Producing `-` + bigint text avoids any per-tier
                    // ambiguity around two's-complement vs sign-magnitude.
                    // Allocation-free: we'd need an allocator to prepend the
                    // `-`, so leave this path to the lowerExprToRef pipeline
                    // (which emits load_const(0) and a unary-op binding).
                    else => {},
                }
            }
        },
        else => {},
    }
    return null;
}

// ============================================================================
// Methods
// ============================================================================

fn lowerMethods(allocator: Allocator, contract: ContractNode, diag: ?*LowerDiagnostic) LowerError![]ANFMethod {
    var result: std.ArrayListUnmanaged(ANFMethod) = .empty;

    // Lower constructor — do NOT register constructor params with addParam;
    // the TS/Go/Rust/Python compilers treat constructor param names as property
    // references (load_prop) rather than parameter references (load_param).
    var reserved_temps: std.StringHashMapUnmanaged(void) = .empty;
    defer reserved_temps.deinit(allocator);
    try collectReservedTemps(allocator, contract, &reserved_temps);

    {
        var ctor_ctx = LowerCtx.init(allocator, contract);
        ctor_ctx.reserved_temps = &reserved_temps;
        ctor_ctx.diagnostic = diag;
        defer ctor_ctx.deinit();
        for (contract.constructor.params) |param| {
            if (isByteType(param.type_info)) ctor_ctx.markByteTyped(param.name);
        }
        try lowerConstructorBody(&ctor_ctx, contract.constructor);
        const bindings = try ctor_ctx.bindings.toOwnedSlice(allocator);
        try result.append(allocator, ANFMethod{
            .name = "constructor",
            .is_public = false,
            .params = contract.constructor.params,
            .bindings = bindings,
            .body = bindings,
        });
    }

    // Issue #109: readonly fields carrying a `/** @embedAlways */` directive
    // must survive DCE into the locking script. A readonly field no method
    // references lowers to no load_prop, so no constructor slot is emitted and
    // the field's deploy-time bytes vanish. We inject a preserved load_prop
    // for each such field into the FIRST public method's body — it keeps the
    // field's constructor-slot placeholder in the deployed script, and stack
    // lowering threads the pushed value through and NIPs it at method end.
    // One slot in the deployed script suffices; every spending branch shares it.
    var embed_injected = false;

    // Lower each method
    for (contract.methods) |method| {
        var method_ctx = LowerCtx.init(allocator, contract);
        method_ctx.reserved_temps = &reserved_temps;
        method_ctx.diagnostic = diag;
        defer method_ctx.deinit();
        // Use the method's source location as default for all bindings in the method.
        method_ctx.current_source_loc = method.source_loc;
        for (method.params) |param| {
            method_ctx.addParam(param.name);
            if (isByteType(param.type_info)) method_ctx.markByteTyped(param.name);
        }

        // Issue #123: a non-default @sighash mode drives the OP_PUSH_TX binding
        // flag for any checkPreimage (auto-injected below, or a manual call) in
        // this method, and rides on the ANF method as a carrier the artifact
        // assembler copies to ABIMethod.sighash_type (omitted for the default).
        var method_sighash: ?i32 = null;
        if (method.sighash_type) |st| {
            if (st != sighash_directive.SIGHASH_DEFAULT) {
                method_ctx.sighash_flag = st;
                method_sighash = st;
            }
        }

        if (contract.parent_class == .stateful_smart_contract and method.is_public) {
            try lowerStatefulPublicMethod(allocator, &method_ctx, method, contract, &embed_injected);
        } else {
            // Issue #109: stateless public methods (and stateless contracts'
            // spending entry points) are lowered here — inject @embedAlways
            // preservation into the first PUBLIC one before its body.
            if (!embed_injected and method.is_public) {
                if (try emitEmbedAlwaysPreservation(&method_ctx, contract)) embed_injected = true;
            }
            try lowerStatements(&method_ctx, method.body);
            const bindings = try method_ctx.bindings.toOwnedSlice(allocator);
            // Private methods can also call the intent intrinsics; append
            // any auto-injected witness params to their ABI. (Private methods
            // are inlined into public bodies via inlinePrivateMethodCall —
            // that path reuses the caller's context so the auto-injection
            // registers at the public method's ABI augmentation step. The
            // private's own ABI is still informative for non-inlined callees.)
            // Fast path: when no intrinsics auto-injected anything, borrow
            // the parser-owned slice unchanged to avoid an extra allocation
            // (matches the pre-Phase-13 behaviour expected by callers that
            // do not own the returned ANFProgram's params slice).
            var params_out: []ParamNode = method.params;
            if (method_ctx.auto_injected_params.items.len > 0) {
                var nonpub_params: std.ArrayListUnmanaged(ParamNode) = .empty;
                for (method.params) |p| try nonpub_params.append(allocator, p);
                for (method_ctx.auto_injected_params.items) |p| {
                    try nonpub_params.append(allocator, p);
                }
                params_out = try nonpub_params.toOwnedSlice(allocator);
            }
            try result.append(allocator, ANFMethod{
                .name = method.name,
                .is_public = method.is_public,
                .params = params_out,
                .bindings = bindings,
                .body = bindings,
                .sighash_type = method_sighash,
            });
        }

        if (contract.parent_class == .stateful_smart_contract and method.is_public) {
            // Build augmented params.
            // Methods that use addOutput, addDataOutput, or mutate state need hashOutputs
            // verification (i.e. change output support).
            const has_data_output = methodHasAddDataOutput(method, contract);
            const needs_change_output = methodMutatesState(method, contract) or methodHasAddOutput(method, contract) or has_data_output;
            // Single-output continuation needs _newAmount to allow changing the UTXO
            // satoshis. Multi-output (addOutput) methods specify amounts explicitly.
            // Methods that emit only data outputs (no addOutput) still run the
            // single-output continuation path for their state continuation, so they
            // also need _newAmount.
            const needs_new_amount = (methodMutatesState(method, contract) or has_data_output) and !methodHasAddOutput(method, contract);

            var aug_params: std.ArrayListUnmanaged(ParamNode) = .empty;
            for (method.params) |param| {
                if (!std.mem.eql(u8, param.type_name, "StatefulContext")) {
                    try aug_params.append(allocator, param);
                }
            }
            if (needs_change_output) {
                try aug_params.append(allocator, .{ .name = "_changePKH", .type_info = .ripemd160, .type_name = "Ripemd160" });
                try aug_params.append(allocator, .{ .name = "_changeAmount", .type_info = .bigint, .type_name = "bigint" });
            }
            if (needs_new_amount) {
                try aug_params.append(allocator, .{ .name = "_newAmount", .type_info = .bigint, .type_name = "bigint" });
            }
            try aug_params.append(allocator, .{ .name = "txPreimage", .type_info = .sig_hash_preimage, .type_name = "SigHashPreimage" });

            // Intent-covenant intrinsic auto-injected witness params (BSVM
            // Phase 13). extractPrevOutputScript adds `_prevOutScript_<i>`
            // (one per distinct literal index referenced in the method);
            // requireOutputP2PKH adds a single `_serialisedOutputs`. Order
            // follows insertion order via auto_injected_params. Appended
            // AFTER txPreimage so unlocking scripts push them adjacent to
            // the preimage (matches existing _changePKH / _changeAmount /
            // _newAmount convention of trailing the user args before the
            // preimage anchor).
            for (method_ctx.auto_injected_params.items) |p| {
                try aug_params.append(allocator, p);
            }

            const bindings = try method_ctx.bindings.toOwnedSlice(allocator);
            try result.append(allocator, ANFMethod{
                .name = method.name,
                .is_public = true,
                .params = try aug_params.toOwnedSlice(allocator),
                .bindings = bindings,
                .body = bindings,
                .sighash_type = method_sighash,
            });
        }
    }

    return try result.toOwnedSlice(allocator);
}

fn lowerConstructorBody(ctx: *LowerCtx, ctor: ConstructorNode) LowerError!void {
    // Always lower super() call — even with zero args, the call must appear in the
    // constructor body to match the TypeScript reference compiler output.
    var arg_refs: std.ArrayListUnmanaged([]const u8) = .empty;
    for (ctor.super_args) |arg| {
        const ref = try lowerExprToRef(ctx, arg);
        try arg_refs.append(ctx.allocator, ref);
    }
    _ = try ctx.emit(.{ .call = .{
        .func = "super",
        .args = try arg_refs.toOwnedSlice(ctx.allocator),
    } });

    // Lower constructor assignments: this.x = param
    for (ctor.assignments) |assign| {
        const value_ref = try lowerExprToRef(ctx, assign.value);
        _ = try ctx.emit(.{ .update_prop = .{
            .name = assign.target,
            .value = value_ref,
        } });
    }
}

/// Issue #109: emit a DCE-surviving preservation `load_prop` for each
/// `@embedAlways` readonly field into the given (public) method context.
/// Returns true when at least one field was injected (so the caller marks the
/// one-shot injection done). The load_prop carries `preserve = true`, so
/// `dce.hasSideEffect` keeps it even though nothing references it; stack
/// lowering then emits the field's constructor-slot placeholder and NIPs the
/// unused value off the stack at method end. The field's bytes therefore remain
/// in the deployed locking script for downstream recovery.
///
/// The TypeScript reference achieves the same via a `load_prop` + `@ref` alias
/// relying on a single-pass DCE. The Zig `ec_optimizer` runs a fixpoint DCE
/// that would strip such an unreferenced alias chain, so the Zig tier marks the
/// injected load_prop directly. The observable output is byte-identical.
fn emitEmbedAlwaysPreservation(ctx: *LowerCtx, contract: ContractNode) LowerError!bool {
    var injected = false;
    for (contract.properties) |prop| {
        if (prop.readonly and prop.embed_always) {
            _ = try ctx.emit(.{ .load_prop = .{ .name = prop.name, .preserve = true } });
            injected = true;
        }
    }
    return injected;
}

fn lowerStatefulPublicMethod(
    allocator: Allocator,
    ctx: *LowerCtx,
    method: MethodNode,
    contract: ContractNode,
    embed_injected: *bool,
) LowerError!void {
    // Methods that use addOutput, addDataOutput, or mutate state need hashOutputs
    // verification (change output support).
    const has_data_output = methodHasAddDataOutput(method, contract);
    const needs_change_output = methodMutatesState(method, contract) or methodHasAddOutput(method, contract) or has_data_output;
    // Single-output continuation needs _newAmount. Methods that emit only data
    // outputs (no addOutput) still run the single-output continuation path, so
    // they also need _newAmount.
    const needs_new_amount = (methodMutatesState(method, contract) or has_data_output) and !methodHasAddOutput(method, contract);

    // Register implicit parameters
    if (needs_change_output) {
        ctx.addParam("_changePKH");
        ctx.addParam("_changeAmount");
        ctx.markByteTyped("_changePKH");
    }
    if (needs_new_amount) {
        ctx.addParam("_newAmount");
    }
    ctx.addParam("txPreimage");
    ctx.markByteTyped("txPreimage");

    // Issue #123: the declared per-method sighash mode (default ALL|FORKID).
    // Drives BOTH the OP_PUSH_TX binding flag (so the derived sig re-computes
    // the tx sighash under this mode) AND the runtime preimage-type assert.
    const sighash_mode: i32 = method.sighash_type orelse sighash_directive.SIGHASH_DEFAULT;
    const is_default_sighash = sighash_mode == sighash_directive.SIGHASH_DEFAULT;

    // Inject checkPreimage(txPreimage). Omit the sighash flag for the default so
    // the ANF (and pinned binding blob) is byte-identical to every existing
    // contract.
    const preimage_ref = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
    const check_result = try ctx.emit(.{ .check_preimage = .{
        .preimage = preimage_ref,
        .sighash_flag = if (is_default_sighash) 0 else sighash_mode,
    } });
    _ = try ctx.emit(.{ .assert = .{ .value = check_result } });

    // GAP-302 / #123: pin the sighash type to the declared mode. Without this
    // check the spend could use a DIFFERENT sighash flag than declared that
    // zeroes out preimage fields the contract (or its continuation) relies on
    // (hashOutputs / hashPrevouts / hashSequence). The value defaults to 0x41
    // (SIGHASH_ALL|FORKID) so existing contracts emit byte-identical ANF.
    const sig_hash_preimage_ref = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
    const sig_hash_type_ref = try ctx.emit(.{ .call = .{
        .func = "extractSigHashType",
        .args = try ctx.allocSlice(&.{sig_hash_preimage_ref}),
    } });
    const expected_sig_hash_ref = try ctx.emit(makeLoadConstInt(sighash_mode));
    const sig_hash_ok_ref = try ctx.emit(.{ .bin_op = .{
        .op = "===",
        .left = sig_hash_type_ref,
        .right = expected_sig_hash_ref,
        .result_type = null,
    } });
    _ = try ctx.emit(.{ .assert = .{ .value = sig_hash_ok_ref } });

    // Deserialize state if there are mutable properties
    const has_mutable_state = for (contract.properties) |p| {
        if (!p.readonly) break true;
    } else false;

    if (has_mutable_state) {
        const preimage_ref3 = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
        _ = try ctx.emit(.{ .deserialize_state = .{ .preimage = preimage_ref3 } });
    }

    // Issue #109: preserve @embedAlways fields at the first user-statement
    // position (after the checkPreimage/deserialize preamble), mirroring where
    // a `const _bind = this.field;` idiom would sit.
    if (!embed_injected.*) {
        if (try emitEmbedAlwaysPreservation(ctx, contract)) embed_injected.* = true;
    }

    // Lower the developer's method body
    try lowerStatements(ctx, method.body);

    // Determine state continuation type.
    //
    // === Continuation-hash construction ===
    //
    // The auto-injected continuation assertion verifies that the spending
    // transaction's hashOutputs field matches a compiler-constructed hash
    // over the outputs this method declares. Outputs are concatenated in
    // the following order before hashing with hash256:
    //
    //   1. state outputs   (from this.addOutput / this.addRawOutput)
    //   2. data outputs    (from this.addDataOutput)
    //   3. change output   (P2PKH to _changePKH, value = _changeAmount)
    //
    // For the "single-output" fast path (no addOutput used, but state is
    // mutated OR data outputs were declared), the state output is computed
    // on the fly from (preimage, stateScript, _newAmount). Data outputs may
    // still be declared in this mode and are inserted BETWEEN the single
    // state output and the change output.
    const add_output_refs = ctx.getAddOutputRefs();
    const add_data_output_refs = ctx.getAddDataOutputRefs();
    _ = allocator;

    if (add_output_refs.len > 0 or add_data_output_refs.len > 0 or methodMutatesState(method, contract)) {
        // Build the P2PKH change output for hashOutputs verification.
        //
        // Issue #116: the SDK's buildCallTransaction OMITS the change output when
        // `change <= 0` (an exact-cover call) and passes `_changeAmount = 0`.
        // Gate the change segment on `_changeAmount != 0` at runtime so the hashed
        // output set matches the SDK at the exact-zero boundary — the segment is
        // the P2PKH change output when non-zero, and empty bytes (cat with empty
        // is a no-op) when zero, reproducing the omission. For any change > 0 the
        // hashed bytes are unchanged; only the emitted script gains the guard.
        const change_pkh_ref = try ctx.emit(.{ .load_param = .{ .name = "_changePKH" } });
        const change_amount_ref = try ctx.emit(.{ .load_param = .{ .name = "_changeAmount" } });
        const zero_ref = try ctx.emit(makeLoadConstInt(0));
        const change_nonzero_ref = try ctx.emit(.{ .bin_op = .{
            .op = "!==",
            .left = change_amount_ref,
            .right = zero_ref,
        } });
        var change_then_ctx = ctx.subContext();
        _ = try change_then_ctx.emit(.{ .call = .{
            .func = "buildChangeOutput",
            .args = try change_then_ctx.allocSlice(&.{ change_pkh_ref, change_amount_ref }),
        } });
        ctx.syncCounter(&change_then_ctx);
        var change_else_ctx = ctx.subContext();
        _ = try change_else_ctx.emit(makeLoadConstString(change_else_ctx.allocator, ""));
        ctx.syncCounter(&change_else_ctx);
        const change_if = try ctx.allocator.create(types.ANFIf);
        change_if.* = .{
            .cond = change_nonzero_ref,
            .then = try change_then_ctx.bindings.toOwnedSlice(ctx.allocator),
            .@"else" = try change_else_ctx.bindings.toOwnedSlice(ctx.allocator),
        };
        const change_output_ref = try ctx.emit(.{ .@"if" = change_if });

        if (add_output_refs.len > 0) {
            // Multi-output: concat all state outputs, then all data outputs,
            // then change output, then hash, verify.
            var accumulated: []const u8 = add_output_refs[0];
            for (add_output_refs[1..]) |aor| {
                accumulated = try ctx.emit(.{ .call = .{
                    .func = "cat",
                    .args = try ctx.allocSlice(&.{ accumulated, aor }),
                } });
            }
            for (add_data_output_refs) |dref| {
                accumulated = try ctx.emit(.{ .call = .{
                    .func = "cat",
                    .args = try ctx.allocSlice(&.{ accumulated, dref }),
                } });
            }
            accumulated = try ctx.emit(.{ .call = .{
                .func = "cat",
                .args = try ctx.allocSlice(&.{ accumulated, change_output_ref }),
            } });
            const hash_ref = try ctx.emit(.{ .call = .{
                .func = "hash256",
                .args = try ctx.allocSlice(&.{accumulated}),
            } });
            const preimage_ref2 = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
            const output_hash_ref = try ctx.emit(.{ .call = .{
                .func = "extractOutputHash",
                .args = try ctx.allocSlice(&.{preimage_ref2}),
            } });
            const eq_ref = try ctx.emit(.{ .bin_op = .{
                .op = "===",
                .left = hash_ref,
                .right = output_hash_ref,
                .result_type = "bytes",
            } });
            _ = try ctx.emit(.{ .assert = .{ .value = eq_ref, .is_auto_injected_state_check = true } });
        } else {
            // Single-output continuation: build raw state output bytes, then
            // splice in declared data outputs, then concat with change,
            // then hash.
            const state_script_ref = try ctx.emit(.{ .get_state_script = {} });
            const preimage_ref2 = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
            const new_amount_ref = try ctx.emit(.{ .load_param = .{ .name = "_newAmount" } });
            const contract_output_ref = try ctx.emit(.{ .call = .{
                .func = "computeStateOutput",
                .args = try ctx.allocSlice(&.{ preimage_ref2, state_script_ref, new_amount_ref }),
            } });
            var accumulated: []const u8 = contract_output_ref;
            for (add_data_output_refs) |dref| {
                accumulated = try ctx.emit(.{ .call = .{
                    .func = "cat",
                    .args = try ctx.allocSlice(&.{ accumulated, dref }),
                } });
            }
            const all_outputs = try ctx.emit(.{ .call = .{
                .func = "cat",
                .args = try ctx.allocSlice(&.{ accumulated, change_output_ref }),
            } });
            const hash_ref = try ctx.emit(.{ .call = .{
                .func = "hash256",
                .args = try ctx.allocSlice(&.{all_outputs}),
            } });
            const preimage_ref4 = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
            const output_hash_ref = try ctx.emit(.{ .call = .{
                .func = "extractOutputHash",
                .args = try ctx.allocSlice(&.{preimage_ref4}),
            } });
            const eq_ref = try ctx.emit(.{ .bin_op = .{
                .op = "===",
                .left = hash_ref,
                .right = output_hash_ref,
                .result_type = "bytes",
            } });
            _ = try ctx.emit(.{ .assert = .{ .value = eq_ref, .is_auto_injected_state_check = true } });
        }
    }
}

// ============================================================================
// LowerCtx -- manages temp variable generation and binding emission
// ============================================================================

/// Shared empty reserved set, so the common contract allocates nothing.
var empty_reserved: std.StringHashMapUnmanaged(void) = .empty;

/// True for exactly the names `LowerCtx.freshTemp` can mint.
fn isTempShaped(name: []const u8) bool {
    if (name.len < 2 or name[0] != 't') return false;
    for (name[1..]) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

/// Collect `t<digits>` declaration names from a statement list.
fn collectDeclNames(
    allocator: Allocator,
    stmts: []const types.Statement,
    out: *std.StringHashMapUnmanaged(void),
) !void {
    for (stmts) |stmt| {
        switch (stmt) {
            .const_decl => |d| if (isTempShaped(d.name)) try out.put(allocator, d.name, {}),
            .let_decl => |d| if (isTempShaped(d.name)) try out.put(allocator, d.name, {}),
            .if_stmt => |s| {
                try collectDeclNames(allocator, s.then_body, out);
                if (s.else_body) |eb| try collectDeclNames(allocator, eb, out);
            },
            .for_stmt => |s| {
                // The loop variable is a declaration too: the other six tiers
                // model `for` init as a VariableDecl node and pick it up there.
                if (isTempShaped(s.var_name)) try out.put(allocator, s.var_name, {});
                try collectDeclNames(allocator, s.body, out);
            },
            else => {},
        }
    }
}

/// Every `t<digits>` identifier the contract's own source binds, so `freshTemp`
/// can never mint a name that shadows one.
///
/// `freshTemp` mints t0, t1, t2, … while `emitNamed` binds the developer's own
/// locals into the SAME binding namespace. Nothing reserved them against each
/// other, so a contract with a local named `t3` got a compiler temp named `t3`
/// written on top of it, and the reference that read the user's value silently
/// resolved to the compiler's.
///
/// That deletes asserts. `const t3 = z - y; const t5 = y - t3;
/// assert(t5 === this.want)` lowered `t5 := load_prop want` over the user's
/// `t5`, leaving `assert(want === want)` — always true, so the locking script
/// carried no guard and any witness could spend it. FAIL-OPEN, and reachable
/// with no branch involved.
///
/// CONTRACT-wide, not method-wide, because private helpers are ANF-INLINED into
/// their callers: a helper local named `t3` is `emitNamed` into the CALLER's
/// binding stream, so a per-method set would miss it.
///
/// Only declarations and parameters are collected. An assignment target must
/// name something already declared or a parameter, so those are covered
/// transitively. Only `t<digits>` names can ever collide, so nothing else is
/// reserved and temp numbering is unchanged for every contract that does not
/// already miscompile — which is what leaves the goldens and the cross-tier hex
/// parity untouched. All seven tiers implement this same rule.
fn collectReservedTemps(
    allocator: Allocator,
    contract: ContractNode,
    out: *std.StringHashMapUnmanaged(void),
) !void {
    // Zig models the constructor as params + assignments, with no statement
    // body, so there are no declarations to walk there — only its params. The
    // other six tiers walk a constructor body that the validator forbids from
    // holding declarations, so the collected set is the same.
    for (contract.constructor.params) |p| {
        if (isTempShaped(p.name)) try out.put(allocator, p.name, {});
    }
    for (contract.methods) |m| try collectMethodReserved(allocator, m, out);
}

fn collectMethodReserved(
    allocator: Allocator,
    m: MethodNode,
    out: *std.StringHashMapUnmanaged(void),
) !void {
    for (m.params) |p| {
        if (isTempShaped(p.name)) try out.put(allocator, p.name, {});
    }
    try collectDeclNames(allocator, m.body, out);
}

const LowerCtx = struct {
    allocator: Allocator,
    contract: ContractNode,
    bindings: std.ArrayListUnmanaged(ANFBinding),
    counter: u32,
    /// `t<digits>` identifiers the contract's own source binds, so `freshTemp`
    /// never mints a name that shadows one. See `collectReservedTemps`.
    reserved_temps: *const std.StringHashMapUnmanaged(void) = &empty_reserved,
    local_names: std.StringHashMapUnmanaged(void),
    param_names: std.StringHashMapUnmanaged(void),
    local_aliases: std.StringHashMapUnmanaged([]const u8),
    local_byte_vars: std.StringHashMapUnmanaged(void),
    add_output_refs: std.ArrayListUnmanaged([]const u8),
    /// Tracks addDataOutput binding refs — data outputs are included in the
    /// continuation hash AFTER state outputs and BEFORE the change output.
    add_data_output_refs: std.ArrayListUnmanaged([]const u8),
    /// Param substitution stack used when inlining a private method's body
    /// directly into this context. While the inlined body lowers, identifier
    /// references to that param resolve to the caller's arg ref instead of
    /// emitting load_param. Stacked so nested inlines compose correctly.
    /// Mirrors TS / Go reference compilers' paramAliasStack.
    param_alias_stack: std.StringHashMapUnmanaged(std.ArrayListUnmanaged([]const u8)),
    /// Current source location — set before lowering each statement, stamped on bindings.
    current_source_loc: ?types.SourceLocation = null,
    /// Intent sub-covenant intrinsics (BSVM Phase 13). Auto-injected witness
    /// params needed by extractPrevOutputScript (`_prevOutScript_<i>`) and
    /// requireOutputP2PKH (`_serialisedOutputs`). Insertion-order list +
    /// dedup set; appended to the method's ABI params list AFTER txPreimage.
    /// Mirrors Go's methodScopeT (compilers/go/frontend/anf_lower.go).
    auto_injected_params: std.ArrayListUnmanaged(ParamNode),
    auto_injected_set: std.StringHashMapUnmanaged(void),
    /// requireOutputP2PKH emits its hashOutputs(preimage) check at most once
    /// per method — flipped on the first call.
    did_emit_hash_outputs_check: bool = false,
    /// Issue #123: the declared non-default `@sighash` flag for the method
    /// being lowered, so a MANUAL checkPreimage(pre) call binds under the same
    /// mode as the method's declared sighash. Null = default ALL|FORKID,
    /// keeping the pinned binding blob unchanged. Propagated into sub-contexts
    /// so a manual call inside an if/for body picks it up.
    sighash_flag: ?i32 = null,
    /// True in every context produced by `subContext()` — inside an if arm, a
    /// loop body, or an inlined helper's block — and false only in the context
    /// a method's own body is lowered into. `liftBranchUpdateProps` walks
    /// `method.body` and does NOT recurse, so an `if` its recogniser accepts is
    /// only actually REWRITTEN at method top level.
    nested: bool = false,
    /// Optional sink for the detail behind a refusal (see `LowerDiagnostic`).
    /// Null when the caller used `lowerToANF`. Propagated into sub-contexts so
    /// a refusal raised inside an if/for body still reaches the caller.
    diagnostic: ?*LowerDiagnostic = null,

    fn init(allocator: Allocator, contract: ContractNode) LowerCtx {
        return .{
            .allocator = allocator,
            .contract = contract,
            .bindings = .empty,
            .counter = 0,
            .local_names = .empty,
            .param_names = .empty,
            .local_aliases = .empty,
            .local_byte_vars = .empty,
            .add_output_refs = .empty,
            .add_data_output_refs = .empty,
            .param_alias_stack = .empty,
            .auto_injected_params = .empty,
            .auto_injected_set = .empty,
        };
    }

    /// A fresh temporary name that no user identifier can shadow.
    fn freshTemp(self: *LowerCtx) ![]const u8 {
        var name = try std.fmt.allocPrint(self.allocator, "t{d}", .{self.counter});
        self.counter += 1;
        while (self.reserved_temps.contains(name)) {
            self.allocator.free(name);
            name = try std.fmt.allocPrint(self.allocator, "t{d}", .{self.counter});
            self.counter += 1;
        }
        return name;
    }

    fn emit(self: *LowerCtx, value: ANFValue) LowerError![]const u8 {
        const name = try self.freshTemp();
        try self.bindings.append(self.allocator, ANFBinding{ .name = name, .value = value, .source_loc = self.current_source_loc });
        return name;
    }

    fn emitNamed(self: *LowerCtx, name: []const u8, value: ANFValue) LowerError!void {
        try self.bindings.append(self.allocator, ANFBinding{ .name = name, .value = value, .source_loc = self.current_source_loc });
    }

    fn addLocal(self: *LowerCtx, name: []const u8) void {
        self.local_names.put(self.allocator, name, {}) catch {};
    }

    fn isLocal(self: *const LowerCtx, name: []const u8) bool {
        return self.local_names.get(name) != null;
    }

    fn addParam(self: *LowerCtx, name: []const u8) void {
        self.param_names.put(self.allocator, name, {}) catch {};
    }

    fn markByteTyped(self: *LowerCtx, name: []const u8) void {
        self.local_byte_vars.put(self.allocator, name, {}) catch {};
    }

    fn isParam(self: *const LowerCtx, name: []const u8) bool {
        return self.param_names.get(name) != null;
    }

    fn setLocalAlias(self: *LowerCtx, local_name: []const u8, binding_name: []const u8) void {
        self.local_aliases.put(self.allocator, local_name, binding_name) catch {};
    }

    fn getLocalAlias(self: *const LowerCtx, local_name: []const u8) ?[]const u8 {
        return self.local_aliases.get(local_name);
    }

    fn pushParamAlias(self: *LowerCtx, name: []const u8, alias_ref: []const u8) void {
        const gop = self.param_alias_stack.getOrPut(self.allocator, name) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }
        gop.value_ptr.append(self.allocator, alias_ref) catch {};
    }

    fn popParamAlias(self: *LowerCtx, name: []const u8) void {
        if (self.param_alias_stack.getPtr(name)) |list_ptr| {
            if (list_ptr.items.len > 0) {
                _ = list_ptr.pop();
            }
            if (list_ptr.items.len == 0) {
                list_ptr.deinit(self.allocator);
                _ = self.param_alias_stack.remove(name);
            }
        }
    }

    fn getParamAlias(self: *const LowerCtx, name: []const u8) ?[]const u8 {
        if (self.param_alias_stack.get(name)) |list| {
            if (list.items.len == 0) return null;
            return list.items[list.items.len - 1];
        }
        return null;
    }

    /// True iff `name` is a private method that (transitively) emits state or
    /// data outputs. Triggers ANF-level inlining so the helper's add_output /
    /// add_data_output refs register on the caller's continuation hash.
    fn shouldInlinePrivate(self: *const LowerCtx, name: []const u8) bool {
        const m = lookupPrivateMethod(self.contract, name) orelse return false;
        return methodHasAddOutput(m, self.contract) or methodHasAddDataOutput(m, self.contract);
    }

    fn addOutputRef(self: *LowerCtx, ref: []const u8) void {
        self.add_output_refs.append(self.allocator, ref) catch {};
    }

    fn getAddOutputRefs(self: *const LowerCtx) []const []const u8 {
        return self.add_output_refs.items;
    }

    /// Track an addDataOutput binding ref — kept separate from state output
    /// refs so the continuation-hash composition can concatenate data
    /// outputs after state outputs and before the change output.
    fn addDataOutputRef(self: *LowerCtx, ref: []const u8) void {
        self.add_data_output_refs.append(self.allocator, ref) catch {};
    }

    fn getAddDataOutputRefs(self: *const LowerCtx) []const []const u8 {
        return self.add_data_output_refs.items;
    }

    fn isProperty(self: *const LowerCtx, name: []const u8) bool {
        for (self.contract.properties) |p| {
            if (std.mem.eql(u8, p.name, name)) return true;
        }
        return false;
    }

    fn subContext(self: *LowerCtx) LowerCtx {
        var sub = LowerCtx.init(self.allocator, self.contract);
        sub.counter = self.counter;
        // Same contract, same namespace: an arm's temps must dodge the same
        // user identifiers the enclosing body does.
        sub.reserved_temps = self.reserved_temps;
        // #123: nested manual checkPreimage inherits the method's mode.
        sub.sighash_flag = self.sighash_flag;
        sub.nested = true;
        // A refusal raised inside the branch must reach the same sink.
        sub.diagnostic = self.diagnostic;
        // Copy local names
        var local_it = self.local_names.iterator();
        while (local_it.next()) |entry| {
            sub.local_names.put(self.allocator, entry.key_ptr.*, {}) catch {};
        }
        // Copy param names
        var param_it = self.param_names.iterator();
        while (param_it.next()) |entry| {
            sub.param_names.put(self.allocator, entry.key_ptr.*, {}) catch {};
        }
        // Copy local aliases
        var alias_it = self.local_aliases.iterator();
        while (alias_it.next()) |entry| {
            sub.local_aliases.put(self.allocator, entry.key_ptr.*, entry.value_ptr.*) catch {};
        }
        // Copy local byte vars
        var byte_it = self.local_byte_vars.iterator();
        while (byte_it.next()) |entry| {
            sub.local_byte_vars.put(self.allocator, entry.key_ptr.*, {}) catch {};
        }
        return sub;
    }

    /// Record the detail behind a refusal about to be returned as a
    /// `LowerError`. A no-op when the caller passed no sink; a formatting /
    /// allocation failure leaves the sink empty rather than masking the
    /// refusal, so the typed error is always what the caller sees.
    fn setDiagnostic(self: *LowerCtx, comptime fmt: []const u8, args: anytype) void {
        const sink = self.diagnostic orelse return;
        sink.message = std.fmt.allocPrint(self.allocator, fmt, args) catch null;
    }

    fn syncCounter(self: *LowerCtx, sub: *const LowerCtx) void {
        if (sub.counter > self.counter) {
            self.counter = sub.counter;
        }
    }

    fn deinit(self: *LowerCtx) void {
        self.local_names.deinit(self.allocator);
        self.param_names.deinit(self.allocator);
        self.local_aliases.deinit(self.allocator);
        self.local_byte_vars.deinit(self.allocator);
        self.add_output_refs.deinit(self.allocator);
        self.add_data_output_refs.deinit(self.allocator);
        var alias_it = self.param_alias_stack.iterator();
        while (alias_it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.param_alias_stack.deinit(self.allocator);
        self.auto_injected_params.deinit(self.allocator);
        self.auto_injected_set.deinit(self.allocator);
    }

    /// Record an intent-intrinsic-injected witness param. Idempotent — a
    /// repeat call with the same name is a no-op. Insertion order is
    /// preserved so the ABI augmentation appends them in source order.
    fn recordAutoInjectedParam(self: *LowerCtx, name: []const u8, type_info: RunarType, type_name: []const u8) void {
        if (self.auto_injected_set.contains(name)) return;
        self.auto_injected_set.put(self.allocator, name, {}) catch return;
        self.auto_injected_params.append(self.allocator, .{
            .name = name,
            .type_info = type_info,
            .type_name = type_name,
        }) catch {};
    }

    /// Allocate a slice of string refs on the arena allocator.
    fn allocSlice(self: *LowerCtx, items: []const []const u8) LowerError![]const []const u8 {
        const result = try self.allocator.alloc([]const u8, items.len);
        @memcpy(result, items);
        return result;
    }
};

// ============================================================================
// Statement lowering
// ============================================================================

fn lowerStatements(ctx: *LowerCtx, stmts: []const Statement) LowerError!void {
    try lowerStatementsWithReads(ctx, stmts, &EMPTY_NAME_SET);
}

/// Lower a statement block, threading down the set of identifiers the enclosing
/// blocks still read after this block ends. Only the block-forming statements
/// (if / for) consume it; see `readsAfterStatement`.
fn lowerStatementsWithReads(ctx: *LowerCtx, stmts: []const Statement, reads_after_block: *const NameSet) LowerError!void {
    for (stmts, 0..) |stmt, i| {
        // Early-return nesting: if a then-block ends with return and there's no else-branch,
        // remaining statements become the else-branch.
        if (stmt == .if_stmt) {
            const if_s = stmt.if_stmt;
            if (if_s.else_body == null and (i + 1 < stmts.len) and branchEndsWithReturn(if_s.then_body)) {
                const remaining = stmts[i + 1 ..];
                try lowerIfStatementWithElse(ctx, if_s.condition, if_s.then_body, remaining, reads_after_block);
                return;
            }
        }
        // Only the block-forming statements need to know what the code after
        // them still reads; computing it for every statement would be quadratic
        // for no benefit.
        switch (stmt) {
            .if_stmt, .for_stmt => {
                var reads_after = try readsAfterStatement(ctx, stmts, i, reads_after_block);
                try lowerStatementWithReads(ctx, stmt, &reads_after);
            },
            else => try lowerStatement(ctx, stmt),
        }
    }
}

/// The identifiers still readable once statement `index` of this block has run:
/// everything the following statements in this block read, plus whatever the
/// enclosing blocks read after this block.
///
/// Used by `lowerIfStatementFull` to tell a branch-merged local that is dead
/// after the `if` (safe) from one that is still live (not representable
/// alongside a branch output — see `branchOutputRejectionReason`).
fn readsAfterStatement(ctx: *LowerCtx, stmts: []const Statement, index: usize, reads_after_block: *const NameSet) LowerError!NameSet {
    var reads = NameSet{};
    var it = reads_after_block.iterator();
    while (it.next()) |entry| {
        try reads.put(ctx.allocator, entry.key_ptr.*, {});
    }
    for (stmts[index + 1 ..]) |stmt| {
        try collectStatementReads(ctx, stmt, &reads);
    }
    return reads;
}

/// Collect every identifier a statement READS. The Zig AST models an assignment
/// target as a bare name, so it never contributes a read; its index expression
/// (when the target is `this.x[i]`) still can.
fn collectStatementReads(ctx: *LowerCtx, stmt: Statement, out: *NameSet) LowerError!void {
    switch (stmt) {
        .const_decl => |d| try collectExpressionReads(ctx, d.value, out),
        .let_decl => |d| {
            if (d.value) |v| try collectExpressionReads(ctx, v, out);
        },
        .assign => |a| {
            if (a.index_target) |ia| try collectExpressionReads(ctx, ia.index, out);
            try collectExpressionReads(ctx, a.value, out);
        },
        .if_stmt => |s| {
            try collectExpressionReads(ctx, s.condition, out);
            for (s.then_body) |inner| try collectStatementReads(ctx, inner, out);
            if (s.else_body) |eb| {
                for (eb) |inner| try collectStatementReads(ctx, inner, out);
            }
        },
        .for_stmt => |s| {
            for (s.body) |inner| try collectStatementReads(ctx, inner, out);
        },
        .assert_stmt => |s| try collectExpressionReads(ctx, s.condition, out),
        .expr_stmt => |s| try collectExpressionReads(ctx, s.expr, out),
        .return_stmt => |maybe_expr| {
            if (maybe_expr) |e| try collectExpressionReads(ctx, e, out);
        },
    }
}

/// Collect every identifier an expression reads.
fn collectExpressionReads(ctx: *LowerCtx, expr: Expression, out: *NameSet) LowerError!void {
    switch (expr) {
        .identifier => |name| try out.put(ctx.allocator, name, {}),
        .binary_op => |b| {
            try collectExpressionReads(ctx, b.left, out);
            try collectExpressionReads(ctx, b.right, out);
        },
        .unary_op => |u| try collectExpressionReads(ctx, u.operand, out),
        .call => |c| {
            for (c.args) |a| try collectExpressionReads(ctx, a, out);
        },
        .method_call => |m| {
            for (m.args) |a| try collectExpressionReads(ctx, a, out);
        },
        .ternary => |t| {
            try collectExpressionReads(ctx, t.condition, out);
            try collectExpressionReads(ctx, t.then_expr, out);
            try collectExpressionReads(ctx, t.else_expr, out);
        },
        .index_access => |ia| {
            try collectExpressionReads(ctx, ia.object, out);
            try collectExpressionReads(ctx, ia.index, out);
        },
        .increment => |i| try collectExpressionReads(ctx, i.operand, out),
        .decrement => |d| try collectExpressionReads(ctx, d.operand, out),
        .array_literal => |elements| {
            for (elements) |e| try collectExpressionReads(ctx, e, out);
        },
        // Literals and `this.x` property access read no locals.
        else => {},
    }
}

fn lowerStatement(ctx: *LowerCtx, stmt: Statement) LowerError!void {
    try lowerStatementWithReads(ctx, stmt, &EMPTY_NAME_SET);
}

fn lowerStatementWithReads(ctx: *LowerCtx, stmt: Statement, reads_after: *const NameSet) LowerError!void {
    // Extract source_loc from the statement variant and set it on the context.
    // All bindings emitted while processing this statement will inherit it.
    const prev_loc = ctx.current_source_loc;
    defer ctx.current_source_loc = prev_loc;
    ctx.current_source_loc = switch (stmt) {
        .const_decl => |d| d.source_loc,
        .let_decl => |d| d.source_loc,
        .assign => |a| a.source_loc,
        .if_stmt => |i| i.source_loc,
        .for_stmt => |f| f.source_loc,
        .assert_stmt => |a| a.source_loc,
        .expr_stmt => |e| e.source_loc,
        .return_stmt => null,
    } orelse ctx.current_source_loc;

    switch (stmt) {
        .const_decl => |decl| {
            const value_ref = try lowerExprToRef(ctx, decl.value);
            ctx.addLocal(decl.name);
            if (isByteTypedExpr(decl.value, ctx)) {
                ctx.local_byte_vars.put(ctx.allocator, decl.name, {}) catch {};
            }
            try ctx.emitNamed(decl.name, makeLoadConstString(ctx.allocator, try refString(ctx.allocator, value_ref)));
        },
        .let_decl => |decl| {
            if (decl.value) |val| {
                const value_ref = try lowerExprToRef(ctx, val);
                ctx.addLocal(decl.name);
                if (isByteTypedExpr(val, ctx)) {
                    ctx.local_byte_vars.put(ctx.allocator, decl.name, {}) catch {};
                }
                try ctx.emitNamed(decl.name, makeLoadConstString(ctx.allocator, try refString(ctx.allocator, value_ref)));
            } else {
                ctx.addLocal(decl.name);
                _ = try ctx.emit(makeLoadConstInt(0));
            }
        },
        .assign => |assign| {
            // Skip Zig discard assignments: _ = self; _ = expr;
            if (std.mem.eql(u8, assign.target, "_")) return;
            const value_ref = try lowerExprToRef(ctx, assign.value);
            // Does this assignment write a contract property?
            //
            // The parsers strip `this.` before building Assign, so the target
            // name alone cannot answer that: a LOCAL that shadows a property
            // name carries the same string. `target_is_property` is the
            // parser's answer and is authoritative when set.
            //
            // The `isProperty` fallback is kept for Assign nodes built without
            // the flag (hand-constructed AST in tests), but is now guarded by
            // `!isLocal`, so a shadowing local is never mistaken for a
            // property write. The read path (`lowerIdentifier`) already
            // resolves isLocal first; matching that order here is what makes
            // the two consistent.
            const writes_property = assign.target_is_property or
                (!ctx.isLocal(assign.target) and ctx.isProperty(assign.target));
            if (writes_property) {
                _ = try ctx.emit(.{ .update_prop = .{
                    .name = assign.target,
                    .value = value_ref,
                } });
            } else if (ctx.isLocal(assign.target)) {
                try ctx.emitNamed(assign.target, makeLoadConstString(ctx.allocator, try refString(ctx.allocator, value_ref)));
            } else {
                _ = try lowerExprToRef(ctx, .{ .identifier = assign.target });
            }
        },
        .if_stmt => |if_s| {
            try lowerIfStatementFull(ctx, if_s.condition, if_s.then_body, if_s.else_body, reads_after);
        },
        .for_stmt => |for_s| {
            try lowerForStatement(ctx, for_s, reads_after);
        },
        .expr_stmt => |expr| {
            _ = try lowerExprToRef(ctx, expr.expr);
        },
        .assert_stmt => |assert_s| {
            const cond_ref = try lowerExprToRef(ctx, assert_s.condition);
            _ = try ctx.emit(.{ .assert = .{ .value = cond_ref } });
        },
        .return_stmt => |maybe_expr| {
            if (maybe_expr) |expr| {
                const ref = try lowerExprToRef(ctx, expr);
                // If the returned ref is not the last emitted binding, emit explicit load
                if (ctx.bindings.items.len > 0 and !std.mem.eql(u8, ctx.bindings.items[ctx.bindings.items.len - 1].name, ref)) {
                    _ = try ctx.emit(makeLoadConstString(ctx.allocator, try refString(ctx.allocator, ref)));
                }
            }
        },
    }
}

fn lowerIfStatementFull(ctx: *LowerCtx, condition: Expression, then_body: []const Statement, else_body: ?[]const Statement, reads_after: *const NameSet) LowerError!void {
    const cond_ref = try lowerExprToRef(ctx, condition);

    // Lower then-block
    var then_ctx = ctx.subContext();
    try lowerStatementsWithReads(&then_ctx, then_body, reads_after);
    ctx.syncCounter(&then_ctx);

    // Lower else-block
    var else_ctx = ctx.subContext();
    if (else_body) |eb| {
        try lowerStatementsWithReads(&else_ctx, eb, reads_after);
    }
    ctx.syncCounter(&else_ctx);

    // 2026-04-30 audit finding F2: when a branch contains output
    // intrinsics, append a cat-chain inside each branch so the
    // branch's terminal value is the concat of its output bytes
    // (state then data, in declaration order). Balances runtime
    // stack effects across branches and lets the parent's
    // continuation hash see one ref per if representing the chosen
    // branch's full output set.
    const branch_has_state_output = then_ctx.getAddOutputRefs().len > 0
        or else_ctx.getAddOutputRefs().len > 0;
    const branch_has_outputs = branch_has_state_output
        or then_ctx.getAddDataOutputRefs().len > 0
        or else_ctx.getAddDataOutputRefs().len > 0;

    var then_output_bytes: []const u8 = "";
    var else_output_bytes: []const u8 = "";
    if (branch_has_outputs) {
        then_output_bytes = try appendBranchOutputConcat(&then_ctx);
        else_output_bytes = try appendBranchOutputConcat(&else_ctx);
    }

    // Branch-merged locals (2 or more). An `if` expression carries exactly ONE
    // value, so the alias below can only rewire post-branch references for a
    // SINGLE merged local. With two or more — or with the arms reassigning
    // DIFFERENT locals — every later reference kept naming the pre-branch
    // binding, i.e. the dead initial value, and stack lowering then registered
    // one stack-map slot for N physical results and resolved every later
    // operand one slot off. Reported privately 2026-08-03; see
    // packages/runar-testing/src/__tests__/branch-merged-locals-vm.test.ts.
    //
    // Fix: give both arms the SAME result set in the SAME order by appending an
    // explicit rebind of every merged local to each arm.
    const merged_locals = try collectBranchMergedLocals(ctx, &then_ctx, &else_ctx);

    if (branch_has_outputs) {
        if (try branchOutputRejectionReason(
            ctx,
            &then_ctx,
            &else_ctx,
            then_output_bytes,
            else_output_bytes,
            merged_locals,
            reads_after,
        )) |reason| {
            ctx.setDiagnostic(
                "Cannot compile conditional that both declares outputs and {s}. " ++
                    "Move the addOutput/addRawOutput/addDataOutput call after the " ++
                    "if-statement.",
                .{reason},
            );
            return LowerError.UnrepresentableBranchOutputs;
        }
    }

    // The `if`'s multi-result contract. Locals first, in the canonical merge
    // order both arms agree on, then the properties either arm writes, in
    // contract declaration order — so all seven tiers derive the same list from
    // the same source. `results[0]` is the deepest slot of the block.
    var arm_props: std.ArrayListUnmanaged([]const u8) = .empty;
    defer arm_props.deinit(ctx.allocator);
    try collectUpdatedProps(ctx, then_ctx.bindings.items, &arm_props);
    try collectUpdatedProps(ctx, else_ctx.bindings.items, &arm_props);

    var result_names: std.ArrayListUnmanaged([]const u8) = .empty;
    defer result_names.deinit(ctx.allocator);
    for (merged_locals) |name| try result_names.append(ctx.allocator, name);
    for (ctx.contract.properties) |prop| {
        for (arm_props.items) |written| {
            if (std.mem.eql(u8, written, prop.name)) {
                try result_names.append(ctx.allocator, prop.name);
                break;
            }
        }
    }

    // The result list is keyed by NAME everywhere downstream, so a local that
    // shares a contract property's name appears TWICE and both entries take the
    // PROPERTY path — the local's value is silently replaced by the property's,
    // and the layout assertion cannot see it because both slots are legitimately
    // named the same. Refuse the exact collision only.
    for (merged_locals) |local_name| {
        for (arm_props.items) |written| {
            if (std.mem.eql(u8, written, local_name)) {
                ctx.setDiagnostic(
                    "Local variable '{s}' shadows contract property 'this.{s}', and " ++
                        "the conditional assigns both. The branch's result slots are " ++
                        "identified by name, so the two cannot be told apart and the " ++
                        "local's value would be silently replaced by the property's. " ++
                        "Rename the local.",
                    .{ local_name, local_name },
                );
                return LowerError.ShadowedResultName;
            }
        }
    }

    // When to materialise the contract instead of leaving the arms to the
    // stack-lowerer's inference:
    //
    //   - two or more merged locals — the pre-existing normalisation. Kept on
    //     exactly its old trigger so the four `__merge$` goldens do not move.
    //   - any result at all when the ELSE arm carries code. This is the new
    //     case, and it is where every measured miscompile lives: one arm
    //     rebinds its local IN PLACE (net depth 0) while the other pushes a
    //     fresh slot (net +1), or an arm writes a property beside a rebound
    //     local, or the two arms write the same properties in a different
    //     order. The arms then leave different LAYOUTS, which no depth or
    //     liveness predicate can see.
    //
    // An `if` WITHOUT an else keeps the preserve-the-old-value path in
    // `lowerIfExpr` (phase 3 copies each missing slot's same-named parent
    // value), which already produces exactly these results by construction —
    // deliberately left intact. An arm that emits outputs is excluded: its
    // single value is the serialised output bytes, and
    // `branchOutputRejectionReason` above already refuses every combination
    // that would need a second result.
    //
    // EXCLUDED: an `if` that liftBranchUpdateProps will rewrite. That pass
    // (deep-review finding C20) turns a conditional-property-assignment chain
    // into one flat single-valued `if` per property plus a top-level
    // update_prop, so the surviving `if`s carry no property result and need no
    // declaration. Appending the normalisation block first would ALSO silently
    // disable that pass: its recogniser requires the arm's last binding to be
    // the update_prop with everything before it side-effect free, and the block
    // adds a second update_prop behind it. TicTacToe's position dispatch is
    // exactly that shape, and losing the lift there produced an unspendable
    // `move` script.
    //
    // The exclusion must be exactly "the lift WILL rewrite this `if`", which is
    // narrower than "the lift's recogniser accepts it" in TWO ways — both were
    // live defects producing an unspendable UTXO: the lift only rewrites chains
    // of TWO OR MORE branches (`collectUpdateBranches` returns a ONE-element
    // list for the assert-false-else guard), and it only walks `method.body`,
    // passing loop bodies and surviving arms through untouched, while
    // `declares_results` is evaluated at EVERY nesting depth.
    //
    // A chain's DEEPEST `if` is never at top level, so it now declares results
    // and carries a normalisation block — which is why `collectUpdateBranches`
    // strips a declared block before matching (`stripDeclaredResults`).
    const lifted_maybe = try collectUpdateBranches(
        ctx.allocator,
        cond_ref,
        then_ctx.bindings.items,
        else_ctx.bindings.items,
    );
    const will_be_lifted = !ctx.nested and
        (if (lifted_maybe) |l| l.len >= 2 else false);
    const declares_results = !branch_has_outputs and !will_be_lifted and
        (merged_locals.len >= 2 or
            (result_names.items.len >= 1 and else_ctx.bindings.items.len > 0));

    if (declares_results) {
        try appendBranchResults(ctx, &then_ctx, result_names.items, arm_props.items);
        ctx.syncCounter(&then_ctx);
        try appendBranchResults(ctx, &else_ctx, result_names.items, arm_props.items);
        ctx.syncCounter(&else_ctx);
    }

    const if_val = try ctx.allocator.create(types.ANFIf);
    if_val.* = .{
        .cond = cond_ref,
        .then = try then_ctx.bindings.toOwnedSlice(ctx.allocator),
        .@"else" = try else_ctx.bindings.toOwnedSlice(ctx.allocator),
        .results = if (declares_results)
            try ctx.allocator.dupe([]const u8, result_names.items)
        else
            &.{},
    };
    const if_name = try ctx.emit(.{ .@"if" = if_val });

    if (branch_has_outputs) {
        // Register the if's value once with the parent's continuation
        // tracker. CRITICAL: pick the right tracker. If either branch
        // produces a STATE output, the parent must take the
        // multi-output continuation path, so we register as a state
        // output ref. If neither branch produces a state output and
        // at least one branch produces a data output, we register as
        // a DATA output ref so the parent keeps its single-output
        // `computeStateOutput` continuation and the data-output
        // bytes splice in BETWEEN the state output and the change
        // output. Without this, a branch with only `addDataOutput`
        // was incorrectly forced onto the multi-output path,
        // dropping the canonical state continuation.
        if (branch_has_state_output) {
            ctx.addOutputRef(if_name);
        } else {
            ctx.addDataOutputRef(if_name);
        }
    }

    // Alias detection: if both branches end by reassigning the same SINGLE
    // local variable. Skipped when the arms were normalised above: there the
    // `if` DECLARES its results, and each one keeps its OWN name through the
    // reconcile in the stack lowerer.
    if (!declares_results and if_val.then.len > 0 and if_val.@"else".len > 0) {
        const then_last = if_val.then[if_val.then.len - 1];
        const else_last = if_val.@"else"[if_val.@"else".len - 1];
        if (std.mem.eql(u8, then_last.name, else_last.name) and ctx.isLocal(then_last.name)) {
            ctx.setLocalAlias(then_last.name, if_name);
        }
    }
}

fn lowerIfStatementWithElse(ctx: *LowerCtx, condition: Expression, then_body: []const Statement, else_body: []const Statement, reads_after: *const NameSet) LowerError!void {
    try lowerIfStatementFull(ctx, condition, then_body, else_body, reads_after);
}

/// Why an `if` whose arms declare outputs cannot be represented — or `null`
/// when it can. The result is the reason clause the diagnostic embeds.
///
/// An `if` expression carries exactly ONE value, and when an arm emits an output
/// that value is already spoken for: it is the output bytes the continuation
/// hash consumes (`appendBranchOutputConcat`). Anything ELSE the arm leaves
/// behind breaks one of two invariants that nothing downstream enforces:
///
///   INV-A  the parent registers the if-expression's value as the branch's
///          contribution to the continuation hash, so "the branch's output
///          bytes" really means "whatever the arm's LAST binding is". A binding
///          that lands after the output — a rebound local, a property write —
///          silently replaces the serialized output with an unrelated value,
///          and the residue drain then physically drops the real output.
///   INV-B  an arm that emits an output AND leaves any other slot the parent
///          can still name — a property write anywhere in the arm, or a rebound
///          local that is still read after the `if` — leaves 2+ results against
///          the ONE stack-map name the stack lowerer registers, desyncing the
///          parent stack by a slot from there on.
///
/// Neither is visible off-chain, so both shipped as permanently unspendable
/// locking scripts. Refuse rather than emit one. See
/// packages/runar-testing/src/__tests__/branch-output-terminal-value-vm.test.ts
/// for the real-Script-VM proof of each shape.
///
/// The clauses are checked in a fixed order so all seven tiers report the same
/// reason for a source that trips more than one.
fn branchOutputRejectionReason(
    ctx: *LowerCtx,
    then_ctx: *const LowerCtx,
    else_ctx: *const LowerCtx,
    then_output_bytes: []const u8,
    else_output_bytes: []const u8,
    merged_locals: []const []const u8,
    reads_after: *const NameSet,
) LowerError!?[]const u8 {
    // 1. Two or more merged locals: normalising them would need a multi-result
    //    `if` node, and the arms' single value is already the output concat.
    if (merged_locals.len >= 2) {
        const names = std.mem.join(ctx.allocator, ", ", merged_locals) catch "";
        return try std.fmt.allocPrint(
            ctx.allocator,
            "merges {d} local variables ({s})",
            .{ merged_locals.len, names },
        );
    }

    const labels = [_][]const u8{ "then", "else" };
    const branches = [_]*const LowerCtx{ then_ctx, else_ctx };
    const output_bytes = [_][]const u8{ then_output_bytes, else_output_bytes };

    // 2. INV-A: the arm's terminal binding must BE its output bytes.
    for (branches, 0..) |branch_ctx, i| {
        const items = branch_ctx.bindings.items;
        if (items.len == 0 or !std.mem.eql(u8, items[items.len - 1].name, output_bytes[i])) {
            return try std.fmt.allocPrint(
                ctx.allocator,
                "continues past its output in the {s}-branch",
                .{labels[i]},
            );
        }
    }

    // 3. INV-B: a property write leaves a slot the parent can still name,
    //    wherever in the arm it sits.
    var written_props: std.ArrayListUnmanaged([]const u8) = .empty;
    for (branches) |branch_ctx| {
        try collectUpdatedProps(ctx, branch_ctx.bindings.items, &written_props);
    }
    if (written_props.items.len > 0) {
        const names = std.mem.join(ctx.allocator, ", ", written_props.items) catch "";
        return try std.fmt.allocPrint(
            ctx.allocator,
            "assigns contract properties ({s}) inside the branch",
            .{names},
        );
    }

    // 4. INV-B: a rebound local that survives the `if` is protected from being
    //    rolled away, so the arm ends one slot deeper than lowerIf accounts for.
    var live_merged: std.ArrayListUnmanaged([]const u8) = .empty;
    for (merged_locals) |name| {
        if (reads_after.contains(name)) try live_merged.append(ctx.allocator, name);
    }
    if (live_merged.items.len > 0) {
        const names = std.mem.join(ctx.allocator, ", ", live_merged.items) catch "";
        return try std.fmt.allocPrint(
            ctx.allocator,
            "reassigns local variables read after it ({s})",
            .{names},
        );
    }

    return null;
}

/// Append every property name an ANF binding list assigns, including the ones
/// nested inside an `if` arm or a `loop` body — a nested write is just as much a
/// named slot the enclosing arm leaves behind.
fn collectUpdatedProps(ctx: *LowerCtx, bindings: []const types.ANFBinding, out: *std.ArrayListUnmanaged([]const u8)) LowerError!void {
    for (bindings) |binding| {
        switch (binding.value) {
            .update_prop => |up| {
                for (out.items) |seen| {
                    if (std.mem.eql(u8, seen, up.name)) break;
                } else {
                    try out.append(ctx.allocator, up.name);
                }
            },
            .@"if" => |if_val| {
                try collectUpdatedProps(ctx, if_val.then, out);
                try collectUpdatedProps(ctx, if_val.@"else", out);
            },
            .loop => |loop_val| try collectUpdatedProps(ctx, loop_val.body, out),
            else => {},
        }
    }
}

fn lowerForStatement(ctx: *LowerCtx, for_s: types.ForStmt, reads_after: *const NameSet) LowerError!void {
    // Resolve the loop's compile-time shape: start value, step direction, and
    // iteration count (issue #121). The loop is unrolled `count` times; on
    // iteration `i` the iterator holds `start + i*step`. Zero-start counting-up
    // loops (start=0, step=1) reproduce the historical `i = 0..count-1`
    // lowering byte-for-byte. Non-zero starts and countdowns (`step = -1`) are
    // now supported — the C-style parsers record the raw operator direction
    // (`descending`) and inclusivity (`inclusive`); range parsers fold any
    // inclusive endpoint into `bound` and stay ascending.
    const start: i64 = for_s.init_value;
    const step: i8 = if (for_s.descending) -1 else 1;

    // count = number of iterations before the condition first turns false.
    const base: i64 = if (for_s.descending) start - for_s.bound else for_s.bound - start;
    const raw: i64 = base + (if (for_s.inclusive) @as(i64, 1) else 0);
    const count: u32 = if (raw > 0) @intCast(raw) else 0;

    // Lower body. The body repeats, so every read anywhere in it is a read that
    // happens after any given statement inside it.
    var body_reads = NameSet{};
    var reads_it = reads_after.iterator();
    while (reads_it.next()) |entry| {
        try body_reads.put(ctx.allocator, entry.key_ptr.*, {});
    }
    for (for_s.body) |s| {
        try collectStatementReads(ctx, s, &body_reads);
    }

    var body_ctx = ctx.subContext();
    try lowerStatementsWithReads(&body_ctx, for_s.body, &body_reads);
    ctx.syncCounter(&body_ctx);

    const loop_val = try ctx.allocator.create(types.ANFLoop);
    loop_val.* = .{
        .count = count,
        .body = try body_ctx.bindings.toOwnedSlice(ctx.allocator),
        .iter_var = for_s.var_name,
        .start = start,
        .step = step,
    };
    _ = try ctx.emit(.{ .loop = loop_val });
}

// ============================================================================
// Expression lowering (the core ANF conversion)
// ============================================================================

fn lowerExprToRef(ctx: *LowerCtx, expr: Expression) LowerError![]const u8 {
    switch (expr) {
        .literal_int => |v| {
            return try ctx.emit(makeLoadConstInt(v));
        },
        .literal_bigint => |s| {
            return try ctx.emit(makeLoadConstBigInt(s));
        },
        .literal_bool => |v| {
            return try ctx.emit(makeLoadConstBool(v));
        },
        .literal_bytes => |v| {
            return try ctx.emit(makeLoadConstString(ctx.allocator, v));
        },
        .identifier => |name| {
            return try lowerIdentifier(ctx, name);
        },
        .property_access => |pa| {
            // Explicit `this.x`: a real contract property always wins, even when
            // a method param shares the name (issue #130). Zig registers declared
            // method params via addParam, so without this isProperty-first check
            // `this.balance` (with a `balance` param) would lower to load_param.
            if (ctx.isProperty(pa.property)) {
                return try ctx.emit(.{ .load_prop = .{ .name = pa.property } });
            }
            // this.txPreimage in StatefulSmartContract -> load_param (an implicit
            // injected param, not a stored property).
            if (ctx.isParam(pa.property)) {
                return try ctx.emit(.{ .load_param = .{ .name = pa.property } });
            }
            if (isStatefulContextParam(ctx, pa.object) and std.mem.eql(u8, pa.property, "txPreimage")) {
                return try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
            }
            // this.x -> load_prop
            return try ctx.emit(.{ .load_prop = .{ .name = pa.property } });
        },
        .binary_op => |bop| {
            // NEW-014: `&&` and `||` SHORT-CIRCUIT. They desugar to the
            // ternary, which stack lowering already emits as real OP_IF /
            // OP_ELSE control flow:
            //
            //     a && b   ==>   a ? b : false
            //     a || b   ==>   a ? true : b
            //
            // They used to lower to `bin_op`, i.e. OP_BOOLAND / OP_BOOLOR —
            // binary stack ops, so BOTH operands were pushed and therefore
            // both evaluated. `spec/semantics.md` §3.7 licensed that with
            // "This is safe in Rúnar because all expressions are pure (no side
            // effects beyond `assert`)". Purity is not TOTALITY: the same
            // document's §10 and §11.3 list division by zero as a runtime
            // failure, and OP_SPLIT / OP_NUM2BIN abort out of range.
            // Evaluating the operand the source skipped therefore aborted the
            // script, and the ordinary defensive guard —
            //
            //     assert(d === 0n || (100n / d) > 1n);
            //
            // — compiled to a locking script the chain rejects for exactly the
            // input the guard exists to protect, while the AST interpreter
            // (which short-circuits, like every surface syntax the frontends
            // accept) reported success. §3.9 already specifies the ternary's
            // untaken arm as unevaluated, so laziness was already in the
            // language; `&&` / `||` were the sole eager outlier.
            //
            // Only SOURCE-level `&&` / `||` desugar here. The compiler still
            // synthesises `bin_op` `&&` / `||` internally to fold if/else-chain
            // guard conditions; those operands are already-bound refs to plain
            // comparison results, so they cannot abort and stay on the cheap
            // opcodes.
            if (bop.op == .and_op or bop.op == .or_op) {
                const is_or = bop.op == .or_op;
                const constant: Expression = .{ .literal_bool = is_or };
                const t = try ctx.allocator.create(types.Ternary);
                t.* = .{
                    .condition = bop.left,
                    .then_expr = if (is_or) constant else bop.right,
                    .else_expr = if (is_or) bop.right else constant,
                };
                return try lowerTernaryExpr(ctx, t);
            }

            const left_ref = try lowerExprToRef(ctx, bop.left);
            const right_ref = try lowerExprToRef(ctx, bop.right);

            var result_type: ?[]const u8 = null;
            const op_str = bop.op.toTsString();

            // For ===, !==, annotate byte-typed operands
            if (bop.op == .eq or bop.op == .neq) {
                if (isByteTypedExpr(bop.left, ctx) or isByteTypedExpr(bop.right, ctx)) {
                    result_type = "bytes";
                }
            }
            // For +, annotate byte-typed operands (OP_CAT)
            if (bop.op == .add) {
                if (isByteTypedExpr(bop.left, ctx) or isByteTypedExpr(bop.right, ctx)) {
                    result_type = "bytes";
                }
            }
            // For &, |, ^, annotate byte-typed operands
            if (bop.op == .bitand or bop.op == .bitor or bop.op == .bitxor) {
                if (isByteTypedExpr(bop.left, ctx) or isByteTypedExpr(bop.right, ctx)) {
                    result_type = "bytes";
                }
            }

            return try ctx.emit(.{ .bin_op = .{
                .op = op_str,
                .left = left_ref,
                .right = right_ref,
                .result_type = result_type,
            } });
        },
        .unary_op => |uop| {
            const operand_ref = try lowerExprToRef(ctx, uop.operand);
            var result_type: ?[]const u8 = null;
            if (uop.op == .bitnot and isByteTypedExpr(uop.operand, ctx)) {
                result_type = "bytes";
            }
            return try ctx.emit(.{ .unary_op = .{
                .op = uop.op.toTsString(),
                .operand = operand_ref,
                .result_type = result_type,
            } });
        },
        .call => |c| {
            return try lowerCallExpr(ctx, c);
        },
        .method_call => |mc| {
            return try lowerMethodCallExpr(ctx, mc);
        },
        .ternary => |t| {
            return try lowerTernaryExpr(ctx, t);
        },
        .index_access => |ia| {
            const obj_ref = try lowerExprToRef(ctx, ia.object);
            const idx_ref = try lowerExprToRef(ctx, ia.index);
            return try ctx.emit(.{ .call = .{
                .func = "__array_access",
                .args = try ctx.allocSlice(&.{ obj_ref, idx_ref }),
            } });
        },
        .increment => |inc| {
            return try lowerIncrementExpr(ctx, inc);
        },
        .decrement => |dec| {
            return try lowerDecrementExpr(ctx, dec);
        },
        .array_literal => |elems| {
            var refs: std.ArrayListUnmanaged([]const u8) = .empty;
            for (elems) |elem| {
                const ref = try lowerExprToRef(ctx, elem);
                try refs.append(ctx.allocator, ref);
            }
            return try ctx.emit(.{ .array_literal = .{
                .elements = try refs.toOwnedSlice(ctx.allocator),
            } });
        },
    }
}

fn lowerIdentifier(ctx: *LowerCtx, name: []const u8) LowerError![]const u8 {
    // 'this' and 'self' are not first-class runtime values in ANF.
    if (std.mem.eql(u8, name, "this") or std.mem.eql(u8, name, "self")) {
        return try ctx.emit(makeLoadConstString(ctx.allocator, "@this"));
    }

    // Param alias takes precedence over normal param lookup. Set when a
    // private method's body is being inlined into this context — the
    // private's param names map to the caller's arg refs.
    if (ctx.getParamAlias(name)) |alias| {
        return alias;
    }

    // Check if it's a registered parameter
    if (ctx.isParam(name)) {
        return try ctx.emit(.{ .load_param = .{ .name = name } });
    }

    // Check if it's a local variable
    if (ctx.isLocal(name)) {
        if (ctx.getLocalAlias(name)) |alias| {
            return alias;
        }
        return name;
    }

    // Check if it's a contract property
    if (ctx.isProperty(name)) {
        return try ctx.emit(.{ .load_prop = .{ .name = name } });
    }

    // Default: treat as parameter
    return try ctx.emit(.{ .load_param = .{ .name = name } });
}

fn isStatefulContextParam(ctx: *const LowerCtx, name: []const u8) bool {
    for (ctx.contract.methods) |method| {
        for (method.params) |param| {
            if (std.mem.eql(u8, param.name, name) and std.mem.eql(u8, param.type_name, "StatefulContext")) {
                return true;
            }
        }
    }
    return false;
}

fn lowerCallExpr(ctx: *LowerCtx, c: *const types.CallExpr) LowerError![]const u8 {
    // super() call
    if (std.mem.eql(u8, c.callee, "super")) {
        const arg_refs = try lowerArgs(ctx, c.args);
        return try ctx.emit(.{ .call = .{
            .func = "super",
            .args = arg_refs,
        } });
    }

    // asm({...}) compiler intrinsic — the parser has already normalised the
    // object-literal argument into three positional args
    // (body, in_arity, out_arity). Lower to a single opaque raw_script ANF
    // binding; the hex body passes through unchanged. Diagnostics for
    // malformed args were already pushed by the validator — here we
    // defensively coerce missing values to safe defaults.
    if (std.mem.eql(u8, c.callee, "asm")) {
        var body_hex: []const u8 = "";
        var in_arity: i32 = 0;
        var out_arity: i32 = 1;
        if (c.args.len >= 1) {
            switch (c.args[0]) {
                .literal_bytes => |bs| body_hex = bs,
                else => {},
            }
        }
        if (c.args.len >= 2) {
            switch (c.args[1]) {
                .literal_int => |i| in_arity = @intCast(i),
                else => {},
            }
        }
        if (c.args.len >= 3) {
            switch (c.args[2]) {
                .literal_int => |i| out_arity = @intCast(i),
                else => {},
            }
        }
        return try ctx.emit(.{ .raw_script = .{
            .bytes = body_hex,
            .in_arity = in_arity,
            .out_arity = out_arity,
        } });
    }

    // assert(expr)
    if (std.mem.eql(u8, c.callee, "assert")) {
        if (c.args.len >= 1) {
            const value_ref = try lowerExprToRef(ctx, c.args[0]);
            return try ctx.emit(.{ .assert = .{ .value = value_ref } });
        }
        const false_ref = try ctx.emit(makeLoadConstBool(false));
        return try ctx.emit(.{ .assert = .{ .value = false_ref } });
    }

    // checkPreimage(preimage)
    if (std.mem.eql(u8, c.callee, "checkPreimage")) {
        if (c.args.len >= 1) {
            const preimage_ref = try lowerExprToRef(ctx, c.args[0]);
            // Issue #123: honour the method's declared @sighash on manual calls.
            return try ctx.emit(.{ .check_preimage = .{
                .preimage = preimage_ref,
                .sighash_flag = ctx.sighash_flag orelse 0,
            } });
        }
    }

    // extractPrevOutputScript(inputIndex_literal, expectedScriptHash) -> ByteString.
    // extractPrevOutputScript(inputIndex_literal, expectedScriptPrefixHash, prefixLen_literal) -> ByteString.
    //
    // Witness-bridge sugar (BSVM Phase 13). Auto-injects a hidden method
    // parameter named `_prevOutScript_<inputIndex>` (one per distinct index
    // in the method body), emits a hash assertion, and returns the witness
    // ref for caller substring extraction.
    //
    // 2-arg form: hash256(witness) === expectedScriptHash. Pins the full
    //   prev-output script byte-for-byte.
    // 3-arg form: hash256(substr(witness, 0, prefixLen)) ===
    //   expectedScriptPrefixHash. Pins the policy prefix only, leaving the
    //   pushdata tail free to vary (BSVM Mode 3 step-in intent templates).
    if (std.mem.eql(u8, c.callee, "extractPrevOutputScript")) {
        if (c.args.len != 2 and c.args.len != 3) {
            return try ctx.emit(makeLoadConstString(ctx.allocator, ""));
        }
        const idx: i64 = switch (c.args[0]) {
            .literal_int => |v| v,
            else => return try ctx.emit(makeLoadConstString(ctx.allocator, "")),
        };
        const param_name = try std.fmt.allocPrint(ctx.allocator, "_prevOutScript_{d}", .{idx});
        ctx.recordAutoInjectedParam(param_name, .byte_string, "ByteString");
        ctx.addParam(param_name);
        const witness_ref = try ctx.emit(.{ .load_param = .{ .name = param_name } });
        const expected_hash_ref = try lowerExprToRef(ctx, c.args[1]);

        // Determine which bytes to hash: full witness (2-arg) or prefix (3-arg).
        // The substr happens at script-execution time; the literal prefixLen
        // is baked into the emitted Stack-IR.
        var bytes_to_hash_ref: []const u8 = witness_ref;
        if (c.args.len == 3) {
            const prefix_len: i64 = switch (c.args[2]) {
                .literal_int => |v| v,
                else => return try ctx.emit(makeLoadConstString(ctx.allocator, "")),
            };
            const zero_ref = try ctx.emit(makeLoadConstInt(0));
            const prefix_len_ref = try ctx.emit(makeLoadConstInt(prefix_len));
            bytes_to_hash_ref = try ctx.emit(.{ .call = .{
                .func = "substr",
                .args = try ctx.allocSlice(&.{ witness_ref, zero_ref, prefix_len_ref }),
            } });
        }

        const actual_hash_ref = try ctx.emit(.{ .call = .{
            .func = "hash256",
            .args = try ctx.allocSlice(&.{bytes_to_hash_ref}),
        } });
        const eq_ref = try ctx.emit(.{ .bin_op = .{
            .op = "===",
            .left = actual_hash_ref,
            .right = expected_hash_ref,
            .result_type = "bytes",
        } });
        _ = try ctx.emit(.{ .assert = .{ .value = eq_ref } });
        return witness_ref;
    }

    // requireOutputP2PKH(outputIndex_literal, pubkeyHash, amount) -> void.
    // Asserts that the tx's output at outputIndex is a standard P2PKH paying
    // `amount` satoshis to `pubkeyHash`. Auto-injects `_serialisedOutputs`
    // (once per method) and emits hash256(serialisedOutputs) ==
    // extractOutputHash(txPreimage) the first time the intrinsic is called
    // in a method body. Subsequent calls in the same method skip the
    // hashOutputs check (already established) and emit only the per-output
    // substring assertion.
    //
    // v1 assumes all outputs in the serialised set are exactly 34 bytes
    // (8-byte LE amount ‖ 0x19 length ‖ 25-byte P2PKH script). Byte offset
    // of output i is i*34.
    if (std.mem.eql(u8, c.callee, "requireOutputP2PKH")) {
        if (c.args.len != 3) {
            return try ctx.emit(makeLoadConstString(ctx.allocator, ""));
        }
        const idx: i64 = switch (c.args[0]) {
            .literal_int => |v| v,
            else => return try ctx.emit(makeLoadConstString(ctx.allocator, "")),
        };

        ctx.recordAutoInjectedParam("_serialisedOutputs", .byte_string, "ByteString");
        ctx.addParam("_serialisedOutputs");

        // Emit the hashOutputs(preimage) check exactly once per method.
        if (!ctx.did_emit_hash_outputs_check) {
            ctx.did_emit_hash_outputs_check = true;
            const serialised_ref0 = try ctx.emit(.{ .load_param = .{ .name = "_serialisedOutputs" } });
            const actual_out_hash_ref = try ctx.emit(.{ .call = .{
                .func = "hash256",
                .args = try ctx.allocSlice(&.{serialised_ref0}),
            } });
            const preimage_ref = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
            const expected_out_hash_ref = try ctx.emit(.{ .call = .{
                .func = "extractOutputHash",
                .args = try ctx.allocSlice(&.{preimage_ref}),
            } });
            const hash_eq_ref = try ctx.emit(.{ .bin_op = .{
                .op = "===",
                .left = actual_out_hash_ref,
                .right = expected_out_hash_ref,
                .result_type = "bytes",
            } });
            _ = try ctx.emit(.{ .assert = .{ .value = hash_eq_ref } });
        }

        // Lower the user-supplied args (pubkeyHash, amount).
        const pubkey_hash_ref = try lowerExprToRef(ctx, c.args[1]);
        const amount_ref = try lowerExprToRef(ctx, c.args[2]);

        // Construct expected P2PKH output bytes:
        //   <amount: 8-byte LE> ‖ 0x19 0x76 0xa9 0x14 ‖ <pubkeyHash: 20 bytes> ‖ 0x88 0xac
        const eight_ref = try ctx.emit(makeLoadConstInt(8));
        const amount_bytes_ref = try ctx.emit(.{ .call = .{
            .func = "num2bin",
            .args = try ctx.allocSlice(&.{ amount_ref, eight_ref }),
        } });
        // 0x19 0x76 0xa9 0x14 — script length byte + OP_DUP OP_HASH160 OP_PUSH20
        const prefix_ref = try ctx.emit(makeLoadConstString(ctx.allocator, "1976a914"));
        // 0x88 0xac — OP_EQUALVERIFY OP_CHECKSIG
        const suffix_ref = try ctx.emit(makeLoadConstString(ctx.allocator, "88ac"));
        const cat1_ref = try ctx.emit(.{ .call = .{
            .func = "cat",
            .args = try ctx.allocSlice(&.{ amount_bytes_ref, prefix_ref }),
        } });
        const cat2_ref = try ctx.emit(.{ .call = .{
            .func = "cat",
            .args = try ctx.allocSlice(&.{ cat1_ref, pubkey_hash_ref }),
        } });
        const expected_output_ref = try ctx.emit(.{ .call = .{
            .func = "cat",
            .args = try ctx.allocSlice(&.{ cat2_ref, suffix_ref }),
        } });

        // Substring extract at idx*34 length 34, assert equal.
        const serialised_ref = try ctx.emit(.{ .load_param = .{ .name = "_serialisedOutputs" } });
        const offset_ref = try ctx.emit(makeLoadConstInt(idx * 34));
        const length_ref = try ctx.emit(makeLoadConstInt(34));
        const extracted_ref = try ctx.emit(.{ .call = .{
            .func = "substr",
            .args = try ctx.allocSlice(&.{ serialised_ref, offset_ref, length_ref }),
        } });
        const out_eq_ref = try ctx.emit(.{ .bin_op = .{
            .op = "===",
            .left = extracted_ref,
            .right = expected_output_ref,
            .result_type = "bytes",
        } });
        return try ctx.emit(.{ .assert = .{ .value = out_eq_ref } });
    }

    // currentBlockHeight() -> bigint. Pure source-level desugar to
    // extractLocktime(this.txPreimage). Only valid in StatefulSmartContract
    // methods (typecheck enforces). No new ANF kind or stack codegen needed.
    if (std.mem.eql(u8, c.callee, "currentBlockHeight")) {
        const preimage_ref = try ctx.emit(.{ .load_param = .{ .name = "txPreimage" } });
        return try ctx.emit(.{ .call = .{
            .func = "extractLocktime",
            .args = try ctx.allocSlice(&.{preimage_ref}),
        } });
    }

    // Check if callee is a contract method (private helper) — emit method_call with @this
    for (ctx.contract.methods) |method| {
        if (std.mem.eql(u8, method.name, c.callee)) {
            const arg_refs = try lowerArgs(ctx, c.args);
            if (ctx.shouldInlinePrivate(c.callee)) {
                return try inlinePrivateMethodCall(ctx, c.callee, arg_refs);
            }
            const this_ref = try ctx.emit(makeLoadConstString(ctx.allocator, "@this"));
            return try ctx.emit(.{ .method_call = .{
                .object = this_ref,
                .method = c.callee,
                .args = arg_refs,
            } });
        }
    }

    // Direct function call: sha256(x), checkSig(sig, pk), etc.
    const arg_refs = try lowerArgs(ctx, c.args);
    return try ctx.emit(.{ .call = .{
        .func = c.callee,
        .args = arg_refs,
    } });
}

fn lowerMethodCallExpr(ctx: *LowerCtx, mc: *const types.MethodCall) LowerError![]const u8 {
    const is_self = std.mem.eql(u8, mc.object, "this") or std.mem.eql(u8, mc.object, "self");
    const is_stateful_ctx = isStatefulContextParam(ctx, mc.object);

    // this.addOutput(satoshis, val1, val2, ...)
    if ((is_self or is_stateful_ctx) and std.mem.eql(u8, mc.method, "addOutput")) {
        const arg_refs = try lowerAddOutputArgs(ctx, mc.args);
        if (arg_refs.len > 0) {
            const ref = try ctx.emit(.{ .add_output = .{
                .satoshis = arg_refs[0],
                .state_values = if (arg_refs.len > 1) arg_refs[1..] else &.{},
                .preimage = "",
            } });
            ctx.addOutputRef(ref);
            return ref;
        }
    }

    // this.addRawOutput(satoshis, scriptBytes)
    if ((is_self or is_stateful_ctx) and std.mem.eql(u8, mc.method, "addRawOutput")) {
        const arg_refs = try lowerArgs(ctx, mc.args);
        if (arg_refs.len >= 2) {
            const ref = try ctx.emit(.{ .add_raw_output = .{
                .satoshis = arg_refs[0],
                .script_bytes = arg_refs[1],
            } });
            ctx.addOutputRef(ref);
            return ref;
        }
    }

    // this.addDataOutput(satoshis, scriptBytes) — wire shape identical to
    // addRawOutput, but included in the continuation hash AFTER state
    // outputs and BEFORE the change output (tracked separately).
    if ((is_self or is_stateful_ctx) and std.mem.eql(u8, mc.method, "addDataOutput")) {
        const arg_refs = try lowerArgs(ctx, mc.args);
        if (arg_refs.len >= 2) {
            const ref = try ctx.emit(.{ .add_data_output = .{
                .satoshis = arg_refs[0],
                .script_bytes = arg_refs[1],
            } });
            ctx.addDataOutputRef(ref);
            return ref;
        }
    }

    // this.getStateScript()
    if ((is_self or is_stateful_ctx) and std.mem.eql(u8, mc.method, "getStateScript")) {
        return try ctx.emit(.{ .get_state_script = {} });
    }

    // SigHash enum members
    if (std.mem.eql(u8, mc.object, "SigHash")) {
        const sig_hash_map = std.StaticStringMap(i64).initComptime(.{
            .{ "ALL", 0x01 },         .{ "NONE", 0x02 },
            .{ "SINGLE", 0x03 },      .{ "FORKID", 0x40 },
            .{ "ANYONECANPAY", 0x80 },
        });
        if (sig_hash_map.get(mc.method)) |val| {
            return try ctx.emit(makeLoadConstInt(val));
        }
    }

    // this.method(...) -> method_call
    if (is_self) {
        const arg_refs = try lowerArgs(ctx, mc.args);
        if (ctx.shouldInlinePrivate(mc.method)) {
            return try inlinePrivateMethodCall(ctx, mc.method, arg_refs);
        }
        const this_ref = try ctx.emit(makeLoadConstString(ctx.allocator, "@this"));
        return try ctx.emit(.{ .method_call = .{
            .object = this_ref,
            .method = mc.method,
            .args = arg_refs,
        } });
    }

    // General member access or method call
    const arg_refs = try lowerArgs(ctx, mc.args);
    const obj_ref = try lowerExprToRef(ctx, .{ .identifier = mc.object });
    return try ctx.emit(.{ .method_call = .{
        .object = obj_ref,
        .method = mc.method,
        .args = arg_refs,
    } });
}

// Inline a private method's body directly into the caller's context. Used
// when the private has continuation-relevant side effects (addOutput /
// addRawOutput / addDataOutput) so that its emitted ANF nodes register
// their output refs on the caller's continuation hash.
//
// The caller's arg refs are mapped onto the private's parameter names via
// pushParamAlias. While the body lowers, identifier references to those
// param names resolve to the caller's ref via lowerIdentifier's alias check.
//
// Recursion across private helpers is forbidden by validation, so this
// always terminates.
fn inlinePrivateMethodCall(ctx: *LowerCtx, method_name: []const u8, arg_refs: []const []const u8) LowerError![]const u8 {
    const method = lookupPrivateMethod(ctx.contract, method_name) orelse {
        const this_ref = try ctx.emit(makeLoadConstString(ctx.allocator, "@this"));
        return try ctx.emit(.{ .method_call = .{
            .object = this_ref,
            .method = method_name,
            .args = arg_refs,
        } });
    };

    // Bind caller arg refs to the private's parameter names.
    var aliased_params: std.ArrayListUnmanaged([]const u8) = .empty;
    defer aliased_params.deinit(ctx.allocator);
    const n = @min(method.params.len, arg_refs.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const param_name = method.params[i].name;
        ctx.pushParamAlias(param_name, arg_refs[i]);
        aliased_params.append(ctx.allocator, param_name) catch {};
    }

    const start_index = ctx.bindings.items.len;
    try lowerStatements(ctx, method.body);
    const end_index = ctx.bindings.items.len;

    // Pop aliases in reverse order so nested inlines compose correctly.
    var j: usize = aliased_params.items.len;
    while (j > 0) {
        j -= 1;
        ctx.popParamAlias(aliased_params.items[j]);
    }

    if (end_index > start_index) {
        return ctx.bindings.items[end_index - 1].name;
    }
    // Empty body — emit a placeholder so the caller has a ref.
    return try ctx.emit(makeLoadConstString(ctx.allocator, "@void"));
}

/// Lower one arm of a ternary, guaranteeing the arm ENDS with the binding that
/// holds its result.
///
/// NEW-016: `lowerExprToRef` returns an existing ref without emitting anything
/// when the arm is a bare identifier — `g ? f : c === 0n` produced `then: []`,
/// an `if` arm with no bindings at all. Stack lowering reads an arm's result
/// off its stack effect, so a +0 arm has no result to adopt and the depth
/// reconcile padded the shortfall with an EMPTY push. The contract compiled
/// clean, the AST interpreter accepted it, and the real engine rejected the
/// spend with "OP_VERIFY requires the top stack value to be truthy" over a
/// stack of `[01, ]` — the arm's `true` replaced by an empty (false) value. An
/// ordinary contract deployed to a permanently unspendable UTXO.
///
/// Aliasing through `load_const "@ref:"` — the same idiom `let x = y` and the
/// increment/decrement lowerings already use — makes the arm's stack effect +1
/// and copies the parent slot instead of trying to move it. The alias is only
/// emitted when the result was NOT produced inside the arm, so every arm that
/// already ended on its own result keeps its exact bytes.
fn lowerTernaryArm(ctx: *LowerCtx, e: Expression) LowerError!void {
    const ref = try lowerExprToRef(ctx, e);
    const ends_on_result = ctx.bindings.items.len > 0 and
        std.mem.eql(u8, ctx.bindings.items[ctx.bindings.items.len - 1].name, ref);
    if (!ends_on_result) {
        _ = try ctx.emit(makeLoadConstString(ctx.allocator, try refString(ctx.allocator, ref)));
    }
}

fn lowerTernaryExpr(ctx: *LowerCtx, t: *const types.Ternary) LowerError![]const u8 {
    const cond_ref = try lowerExprToRef(ctx, t.condition);

    var then_ctx = ctx.subContext();
    try lowerTernaryArm(&then_ctx, t.then_expr);
    ctx.syncCounter(&then_ctx);

    var else_ctx = ctx.subContext();
    try lowerTernaryArm(&else_ctx, t.else_expr);
    ctx.syncCounter(&else_ctx);

    const if_val = try ctx.allocator.create(types.ANFIf);
    if_val.* = .{
        .cond = cond_ref,
        .then = try then_ctx.bindings.toOwnedSlice(ctx.allocator),
        .@"else" = try else_ctx.bindings.toOwnedSlice(ctx.allocator),
    };
    return try ctx.emit(.{ .@"if" = if_val });
}

fn lowerAddOutputArgs(ctx: *LowerCtx, args: []const Expression) LowerError![]const []const u8 {
    if (args.len == 2) {
        switch (args[1]) {
            .array_literal => |elems| {
                var refs: std.ArrayListUnmanaged([]const u8) = .empty;
                try refs.append(ctx.allocator, try lowerExprToRef(ctx, args[0]));
                for (elems) |elem| {
                    try refs.append(ctx.allocator, try lowerExprToRef(ctx, elem));
                }
                return try refs.toOwnedSlice(ctx.allocator);
            },
            else => {},
        }
    }
    return try lowerArgs(ctx, args);
}

fn lowerIncrementExpr(ctx: *LowerCtx, inc: *const types.IncrementExpr) LowerError![]const u8 {
    const operand_ref = try lowerExprToRef(ctx, inc.operand);
    const one_ref = try ctx.emit(makeLoadConstInt(1));
    const result = try ctx.emit(.{ .bin_op = .{
        .op = "+",
        .left = operand_ref,
        .right = one_ref,
    } });

    // If operand is a named variable, update it
    switch (inc.operand) {
        .identifier => |name| {
            try ctx.emitNamed(name, makeLoadConstString(ctx.allocator, try refString(ctx.allocator, result)));
        },
        .property_access => |pa| {
            if (isReadonlyProperty(ctx.contract.properties, pa.property)) {
                return error.UnsupportedExpression; // cannot increment readonly property
            }
            _ = try ctx.emit(.{ .update_prop = .{
                .name = pa.property,
                .value = result,
            } });
        },
        else => {},
    }

    if (inc.prefix) return result;
    return operand_ref;
}

fn lowerDecrementExpr(ctx: *LowerCtx, dec: *const types.DecrementExpr) LowerError![]const u8 {
    const operand_ref = try lowerExprToRef(ctx, dec.operand);
    const one_ref = try ctx.emit(makeLoadConstInt(1));
    const result = try ctx.emit(.{ .bin_op = .{
        .op = "-",
        .left = operand_ref,
        .right = one_ref,
    } });

    // If operand is a named variable, update it
    switch (dec.operand) {
        .identifier => |name| {
            try ctx.emitNamed(name, makeLoadConstString(ctx.allocator, try refString(ctx.allocator, result)));
        },
        .property_access => |pa| {
            if (isReadonlyProperty(ctx.contract.properties, pa.property)) {
                return error.UnsupportedExpression; // cannot decrement readonly property
            }
            _ = try ctx.emit(.{ .update_prop = .{
                .name = pa.property,
                .value = result,
            } });
        },
        else => {},
    }

    if (dec.prefix) return result;
    return operand_ref;
}

fn lowerArgs(ctx: *LowerCtx, args: []const Expression) LowerError![]const []const u8 {
    if (args.len == 0) return &.{};
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    for (args) |arg| {
        const ref = try lowerExprToRef(ctx, arg);
        try result.append(ctx.allocator, ref);
    }
    return try result.toOwnedSlice(ctx.allocator);
}

// ============================================================================
// ANFValue constructors
// ============================================================================

fn makeLoadConstInt(val: i64) ANFValue {
    return .{ .load_const = .{ .value = .{ .integer = val } } };
}

/// Wrap an oversize decimal-text integer literal (already validated by the
/// frontend parser as ASCII digits with optional leading `-`, no `n`
/// suffix) in a `load_const` ANF node. Mirrors Go's `makeLoadConstInt` and
/// Python's `_make_load_const_int` for the overflow path. The text is held
/// by reference: the parser owns the backing buffer (its arena outlives
/// ANF lowering), so we don't dupe here.
fn makeLoadConstBigInt(decimal: []const u8) ANFValue {
    return .{ .load_const = .{ .value = .{ .big_integer = decimal } } };
}

fn makeLoadConstBool(val: bool) ANFValue {
    return .{ .load_const = .{ .value = .{ .boolean = val } } };
}

/// The locals from the enclosing scope that either arm of an if-statement
/// reassigns, in a canonical order both arms can agree on: the then-arm's
/// reassignments in order of last rebind, then the else-only ones in the same
/// order.
///
/// Only names the PARENT already knows as locals count — subContext copies the
/// local-name set by value, so a local declared inside a branch never reaches
/// the parent's set and is correctly excluded (it is not live after the if).
fn collectBranchMergedLocals(
    ctx: *LowerCtx,
    then_ctx: *LowerCtx,
    else_ctx: *LowerCtx,
) LowerError![]const []const u8 {
    var merged: std.ArrayListUnmanaged([]const u8) = .empty;
    for ([_]*LowerCtx{ then_ctx, else_ctx }) |branch| {
        var arm: std.ArrayListUnmanaged([]const u8) = .empty;
        defer arm.deinit(ctx.allocator);
        for (branch.bindings.items) |b| {
            if (!ctx.isLocal(b.name)) continue;
            var seen = false;
            for (arm.items, 0..) |existing, i| {
                if (std.mem.eql(u8, existing, b.name)) {
                    // Move to the back: canonical order is last rebind.
                    _ = arm.orderedRemove(i);
                    try arm.append(ctx.allocator, b.name);
                    seen = true;
                    break;
                }
            }
            if (!seen) try arm.append(ctx.allocator, b.name);
        }
        for (arm.items) |name| {
            var dup = false;
            for (merged.items) |existing| {
                if (std.mem.eql(u8, existing, name)) {
                    dup = true;
                    break;
                }
            }
            if (!dup) try merged.append(ctx.allocator, name);
        }
    }
    return merged.toOwnedSlice(ctx.allocator);
}

/// Append the canonical result block to one arm of an if-statement: a copy of
/// every declared result, in the declared order, rebound under its own name.
/// This is what makes the `if` node's `results` contract true rather than
/// hoped-for.
///
/// Two passes on purpose. Pass 1 always COPIES: for a LOCAL, `@ref:<local>`
/// resolves to the arm's own new value if it rebound one, else to the
/// enclosing scope's value; for a PROPERTY, `load_prop` picks the arm's updated
/// slot when the arm wrote it and otherwise the enclosing value. Either way
/// stack lowering picks (never rolls) it, because a declared result is
/// outer-protected. Pass 2 always CONSUMES, because the temps are bound in this
/// arm and this is their last use. The arm's stack effect is therefore exactly
/// +N regardless of which of the N results it assigned.
///
/// Semantically a no-op for the off-chain ANF interpreters: every binding is an
/// ordinary read-then-write of a value the arm already holds.
fn appendBranchResults(
    ctx: *LowerCtx,
    branch_ctx: *LowerCtx,
    result_names: []const []const u8,
    props: []const []const u8,
) LowerError!void {
    _ = ctx;
    for (result_names, 0..) |name, i| {
        const temp = try std.fmt.allocPrint(
            branch_ctx.allocator,
            "{s}{d}",
            .{ types.merged_local_temp_prefix, i },
        );
        if (containsName(props, name)) {
            try branch_ctx.emitNamed(temp, .{ .load_prop = .{ .name = name } });
        } else {
            try branch_ctx.emitNamed(temp, makeLoadConstString(
                branch_ctx.allocator,
                try refString(branch_ctx.allocator, name),
            ));
        }
    }
    for (result_names, 0..) |name, i| {
        const temp = try std.fmt.allocPrint(
            branch_ctx.allocator,
            "{s}{d}",
            .{ types.merged_local_temp_prefix, i },
        );
        if (containsName(props, name)) {
            _ = try branch_ctx.emit(.{ .update_prop = .{ .name = name, .value = temp } });
        } else {
            try branch_ctx.emitNamed(name, makeLoadConstString(
                branch_ctx.allocator,
                try refString(branch_ctx.allocator, temp),
            ));
        }
    }
}

fn containsName(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |h| {
        if (std.mem.eql(u8, h, needle)) return true;
    }
    return false;
}

fn makeLoadConstString(allocator: Allocator, val: []const u8) ANFValue {
    _ = allocator;
    return .{ .load_const = .{ .value = .{ .string = val } } };
}

/// Concatenate a branch's output refs (state then data, in
/// declaration order) into a single bytes-ref appended to the
/// branch's bindings. If the branch has no outputs, emits an empty
/// `load_const` so the branch still leaves one item on the stack —
/// required to balance the if's branch shapes when the OTHER branch
/// has outputs. 2026-04-30 audit finding F2 fix.
fn appendBranchOutputConcat(branch_ctx: *LowerCtx) LowerError![]const u8 {
    const state_refs = branch_ctx.getAddOutputRefs();
    const data_refs = branch_ctx.getAddDataOutputRefs();
    const total = state_refs.len + data_refs.len;
    if (total == 0) {
        return try branch_ctx.emit(makeLoadConstString(branch_ctx.allocator, ""));
    }
    var all_refs: std.ArrayListUnmanaged([]const u8) = .empty;
    defer all_refs.deinit(branch_ctx.allocator);
    try all_refs.appendSlice(branch_ctx.allocator, state_refs);
    try all_refs.appendSlice(branch_ctx.allocator, data_refs);
    if (all_refs.items.len == 1) return all_refs.items[0];
    var accumulated = all_refs.items[0];
    for (all_refs.items[1..]) |next_ref| {
        const args = try branch_ctx.allocator.alloc([]const u8, 2);
        args[0] = accumulated;
        args[1] = next_ref;
        accumulated = try branch_ctx.emit(.{ .call = .{ .func = "cat", .args = args } });
    }
    return accumulated;
}

/// Create an "@ref:NAME" string for local variable aliasing.
fn refString(allocator: Allocator, name: []const u8) LowerError![]const u8 {
    return try std.fmt.allocPrint(allocator, "@ref:{s}", .{name});
}

// ============================================================================
// Property helpers
// ============================================================================

fn isReadonlyProperty(properties: []const PropertyNode, name: []const u8) bool {
    for (properties) |p| {
        if (std.mem.eql(u8, p.name, name)) return p.readonly;
    }
    return false;
}

// ============================================================================
// State mutation + intrinsic-call analysis (recursive across private calls)
// ============================================================================
//
// Mirrors `packages/runar-compiler/src/passes/side-effect-summary.ts` —
// side effects detected here include those reachable transitively through
// private-method calls, not just direct ones in the public method body.
// This is the F1+F3 fix from the 2026-04-30 TS compiler audit. Without
// recursion, a public method that delegates state mutation or an
// addOutput / addDataOutput intrinsic to a private helper would be
// silently classified as terminal — the ABI would omit `_changePKH`,
// `_changeAmount`, `_newAmount`, and the deployed locking script would
// carry no `hashOutputs` continuation.

fn lookupPrivateMethod(contract: ContractNode, name: []const u8) ?MethodNode {
    for (contract.methods) |m| {
        if (!m.is_public and std.mem.eql(u8, m.name, name)) return m;
    }
    return null;
}

// Maximum depth for the private-call recursion. Validation should
// reject recursion in private methods, so this only triggers under
// pathological inputs that bypass the validator.
const MAX_PRIVATE_CALL_DEPTH: u32 = 64;

fn methodMutatesState(method: MethodNode, contract: ContractNode) bool {
    var has_mutable = false;
    for (contract.properties) |p| {
        if (!p.readonly) {
            has_mutable = true;
            break;
        }
    }
    if (!has_mutable) return false;

    return bodyMutatesStateRec(method.body, contract, 0);
}

fn bodyMutatesStateRec(stmts: []const Statement, contract: ContractNode, depth: u32) bool {
    if (depth > MAX_PRIVATE_CALL_DEPTH) return false;
    for (stmts) |stmt| {
        if (stmtMutatesStateRec(stmt, contract, depth)) return true;
    }
    return false;
}

fn stmtMutatesStateRec(stmt: Statement, contract: ContractNode, depth: u32) bool {
    switch (stmt) {
        .assign => |assign| {
            for (contract.properties) |p| {
                if (!p.readonly and std.mem.eql(u8, p.name, assign.target)) return true;
            }
            return false;
        },
        .expr_stmt => |expr| return exprMutatesStateRec(expr.expr, contract, depth),
        .if_stmt => |if_s| {
            if (bodyMutatesStateRec(if_s.then_body, contract, depth)) return true;
            if (if_s.else_body) |eb| {
                if (bodyMutatesStateRec(eb, contract, depth)) return true;
            }
            return false;
        },
        .for_stmt => |for_s| return bodyMutatesStateRec(for_s.body, contract, depth),
        .return_stmt => |maybe_expr| {
            if (maybe_expr) |expr| {
                return exprMutatesStateRec(expr, contract, depth);
            }
            return false;
        },
        else => return false,
    }
}

fn exprMutatesStateRec(expr: Expression, contract: ContractNode, depth: u32) bool {
    switch (expr) {
        .increment => |inc| {
            switch (inc.operand) {
                .property_access => |pa| {
                    for (contract.properties) |p| {
                        if (!p.readonly and std.mem.eql(u8, p.name, pa.property)) return true;
                    }
                },
                else => {},
            }
        },
        .decrement => |dec| {
            switch (dec.operand) {
                .property_access => |pa| {
                    for (contract.properties) |p| {
                        if (!p.readonly and std.mem.eql(u8, p.name, pa.property)) return true;
                    }
                },
                else => {},
            }
        },
        .call => |call| {
            // Bareword call: callee is the function name. Recurse into
            // a private helper if the name matches one.
            if (lookupPrivateMethod(contract, call.callee)) |target| {
                if (bodyMutatesStateRec(target.body, contract, depth + 1)) return true;
            }
            for (call.args) |arg| {
                if (exprMutatesStateRec(arg, contract, depth)) return true;
            }
        },
        .method_call => |mc| {
            // this.X / self.X — recurse into the helper.
            if (lookupPrivateMethod(contract, mc.method)) |target| {
                if (bodyMutatesStateRec(target.body, contract, depth + 1)) return true;
            }
            for (mc.args) |arg| {
                if (exprMutatesStateRec(arg, contract, depth)) return true;
            }
        },
        else => {},
    }
    return false;
}

// ============================================================================
// addOutput / addDataOutput detection (recursive across private calls)
// ============================================================================
//
// Like methodMutatesState, recurses into private-method bodies so a public
// method that delegates an addOutput / addDataOutput intrinsic to a
// private helper is correctly classified.

fn methodHasAddOutput(method: MethodNode, contract: ContractNode) bool {
    return bodyHasIntrinsicCallRec(method.body, method.params, contract, &STATE_OUTPUT_METHODS, 0);
}

/// Return true when a method body contains at least one this.addDataOutput call.
fn methodHasAddDataOutput(method: MethodNode, contract: ContractNode) bool {
    return bodyHasIntrinsicCallRec(method.body, method.params, contract, &DATA_OUTPUT_METHODS, 0);
}

const STATE_OUTPUT_METHODS = [_][]const u8{ "addOutput", "addRawOutput" };
const DATA_OUTPUT_METHODS = [_][]const u8{"addDataOutput"};

fn bodyHasIntrinsicCallRec(
    stmts: []const Statement,
    params: []const ParamNode,
    contract: ContractNode,
    names: []const []const u8,
    depth: u32,
) bool {
    if (depth > MAX_PRIVATE_CALL_DEPTH) return false;
    for (stmts) |stmt| {
        if (stmtHasIntrinsicCallRec(stmt, params, contract, names, depth)) return true;
    }
    return false;
}

fn stmtHasIntrinsicCallRec(
    stmt: Statement,
    params: []const ParamNode,
    contract: ContractNode,
    names: []const []const u8,
    depth: u32,
) bool {
    switch (stmt) {
        .expr_stmt => |expr| return exprHasIntrinsicCallRec(expr.expr, params, contract, names, depth),
        .if_stmt => |if_s| {
            if (bodyHasIntrinsicCallRec(if_s.then_body, params, contract, names, depth)) return true;
            if (if_s.else_body) |eb| {
                if (bodyHasIntrinsicCallRec(eb, params, contract, names, depth)) return true;
            }
            return false;
        },
        .for_stmt => |for_s| return bodyHasIntrinsicCallRec(for_s.body, params, contract, names, depth),
        // Ruby's parse_ruby promotes a private method's trailing
        // expression-statement to a return-statement for implicit-return
        // semantics. Walk the return value the same way.
        .return_stmt => |maybe_expr| {
            if (maybe_expr) |expr| {
                return exprHasIntrinsicCallRec(expr, params, contract, names, depth);
            }
            return false;
        },
        else => return false,
    }
}

fn exprHasIntrinsicCallRec(
    expr: Expression,
    params: []const ParamNode,
    contract: ContractNode,
    names: []const []const u8,
    depth: u32,
) bool {
    switch (expr) {
        .method_call => |mc| {
            if (std.mem.eql(u8, mc.object, "this") or std.mem.eql(u8, mc.object, "self") or paramIsStatefulContext(params, mc.object)) {
                // Direct intrinsic match.
                for (names) |n| {
                    if (std.mem.eql(u8, mc.method, n)) return true;
                }
                // Recurse into private helper if this is a method call
                // on `this` / `self` / stateful-context.
                if (lookupPrivateMethod(contract, mc.method)) |target| {
                    if (bodyHasIntrinsicCallRec(target.body, target.params, contract, names, depth + 1)) return true;
                }
            }
        },
        .call => |call| {
            // Bareword identifier call on a private helper.
            if (lookupPrivateMethod(contract, call.callee)) |target| {
                if (bodyHasIntrinsicCallRec(target.body, target.params, contract, names, depth + 1)) return true;
            }
        },
        else => {},
    }
    return false;
}

fn paramIsStatefulContext(params: []const ParamNode, name: []const u8) bool {
    for (params) |param| {
        if (std.mem.eql(u8, param.name, name) and std.mem.eql(u8, param.type_name, "StatefulContext")) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Helpers
// ============================================================================

fn branchEndsWithReturn(stmts: []const Statement) bool {
    if (stmts.len == 0) return false;
    const last = stmts[stmts.len - 1];
    switch (last) {
        .return_stmt => return true,
        .if_stmt => |if_s| {
            if (if_s.else_body) |eb| {
                return branchEndsWithReturn(if_s.then_body) and branchEndsWithReturn(eb);
            }
            return false;
        },
        else => return false,
    }
}

// ============================================================================
// liftBranchUpdateProps — flatten if-else chains that write properties
// ============================================================================
//
// Mirrors the TypeScript reference compiler's liftBranchUpdateProps
// (packages/runar-compiler/src/passes/04-anf-lower.ts) and Go/Rust/Ruby ports.
//
// Transforms if-else chains where each branch ends with update_prop into
// flat conditional assignments. This is critical for stateful contracts
// because Bitcoin Script requires ALL state fields to be explicitly on the
// stack after method execution — nested update_props leave phantom stack
// entries in stack lowering.
//
// Before:
//   if (pos === 0) { this.c0 = turn; }
//   else if (pos === 1) { this.c1 = turn; }
//   else { assert(false); }
//
// After:
//   this.c0 = (pos === 0)           ? turn : this.c0;
//   this.c1 = (!cond0 && pos === 1) ? turn : this.c1;

const UpdateBranch = struct {
    cond_setup_bindings: []const ANFBinding,
    cond_ref: ?[]const u8, // null for final else
    prop_name: []const u8,
    value_bindings: []const ANFBinding,
    value_ref: []const u8,
};

/// Find the max temp index (e.g. "t47" → 47) in a binding tree.
fn maxTempIndex(bindings: []const ANFBinding) i64 {
    var max: i64 = -1;
    for (bindings) |b| {
        if (b.name.len > 1 and b.name[0] == 't') {
            var n: i64 = 0;
            var valid = true;
            for (b.name[1..]) |ch| {
                if (ch >= '0' and ch <= '9') {
                    n = n * 10 + (ch - '0');
                } else {
                    valid = false;
                    break;
                }
            }
            if (valid and n > max) max = n;
        }
        switch (b.value) {
            .@"if" => |ifv| {
                const t = maxTempIndex(ifv.then);
                if (t > max) max = t;
                const e = maxTempIndex(ifv.@"else");
                if (e > max) max = e;
            },
            .loop => |lp| {
                const t = maxTempIndex(lp.body);
                if (t > max) max = t;
            },
            else => {},
        }
    }
    return max;
}

/// Check if a binding value is side-effect-free (safe to hoist).
/// F-003: every ANFValue variant is enumerated explicitly (no `else`) so
/// adding a new variant fails at Zig compile time here instead of silently
/// defaulting to "not pure" — which would conservatively block hoisting but
/// hide the missed dispatch update.
fn isSideEffectFree(v: ANFValue) bool {
    return switch (v) {
        .load_prop, .load_param, .load_const, .bin_op, .unary_op => true,
        .call,
        .method_call,
        .@"if",
        .loop,
        .assert,
        .update_prop,
        .get_state_script,
        .check_preimage,
        .deserialize_state,
        .add_output,
        .add_raw_output,
        .add_data_output,
        .array_literal,
        .raw_script,
        => false,
    };
}

fn allBindingsSideEffectFree(bindings: []const ANFBinding) bool {
    for (bindings) |b| {
        if (!isSideEffectFree(b.value)) return false;
    }
    return true;
}

/// Extract the update_prop target from a branch's last binding.
/// Returns null if the branch doesn't end with a simple update_prop.
const BranchUpdate = struct {
    prop_name: []const u8,
    value_bindings: []const ANFBinding,
    value_ref: []const u8,
};

fn extractBranchUpdate(bindings: []const ANFBinding) ?BranchUpdate {
    if (bindings.len == 0) return null;
    const last = bindings[bindings.len - 1];
    switch (last.value) {
        .update_prop => |up| {
            const value_bindings = bindings[0 .. bindings.len - 1];
            if (!allBindingsSideEffectFree(value_bindings)) return null;
            return .{
                .prop_name = up.name,
                .value_bindings = value_bindings,
                .value_ref = up.value,
            };
        },
        else => return null,
    }
}

/// Check if an else branch is just `assert(false)` — unreachable dead code.
fn isAssertFalseElse(bindings: []const ANFBinding) bool {
    if (bindings.len == 0) return false;
    const last = bindings[bindings.len - 1];
    const assert_ref = switch (last.value) {
        .assert => |a| a.value,
        else => return false,
    };
    for (bindings) |b| {
        if (std.mem.eql(u8, b.name, assert_ref)) {
            switch (b.value) {
                .load_const => |lc| switch (lc.value) {
                    .boolean => |bv| return !bv,
                    else => return false,
                },
                else => return false,
            }
        }
    }
    return false;
}

/// An arm with its declared-results block removed.
///
/// `appendBranchResults` adds exactly `2 * results.len` trailing bindings to
/// each arm of an `if` that declares results. They are a materialisation
/// mechanism, not program logic, and they hide the arm's real shape from this
/// pass. A dispatch chain's deepest `if` is nested by definition, so it declares
/// results; without this the enclosing chain stops being recognised and
/// TicTacToe's position dispatch loses the C20 lift (an unspendable script).
fn stripDeclaredResults(bindings: []const ANFBinding, results: []const []const u8) []const ANFBinding {
    if (results.len == 0) return bindings;
    const drop = 2 * results.len;
    if (bindings.len <= drop) return bindings[0..0];
    return bindings[0 .. bindings.len - drop];
}

/// Recursively collect update branches from a nested if-else chain.
/// Returns null if the chain cannot be flattened.
fn collectUpdateBranches(
    allocator: Allocator,
    if_cond: []const u8,
    then_bindings: []const ANFBinding,
    else_bindings: []const ANFBinding,
) LowerError!?[]UpdateBranch {
    const then_update = extractBranchUpdate(then_bindings) orelse return null;

    var branches: std.ArrayListUnmanaged(UpdateBranch) = .empty;
    try branches.append(allocator, .{
        .cond_setup_bindings = &.{},
        .cond_ref = if_cond,
        .prop_name = then_update.prop_name,
        .value_bindings = then_update.value_bindings,
        .value_ref = then_update.value_ref,
    });

    if (else_bindings.len == 0) {
        branches.deinit(allocator);
        return null;
    }

    // Check if else is another if (else-if chain)
    const last_else = else_bindings[else_bindings.len - 1];
    switch (last_else.value) {
        .@"if" => |inner_if| {
            const cond_setup = else_bindings[0 .. else_bindings.len - 1];
            if (!allBindingsSideEffectFree(cond_setup)) {
                branches.deinit(allocator);
                return null;
            }

            const inner_maybe = try collectUpdateBranches(
                allocator,
                inner_if.cond,
                stripDeclaredResults(inner_if.then, inner_if.results),
                stripDeclaredResults(inner_if.@"else", inner_if.results),
            );
            const inner = inner_maybe orelse {
                branches.deinit(allocator);
                return null;
            };

            // Prepend condition setup to first inner branch
            const merged = try allocator.alloc(ANFBinding, cond_setup.len + inner[0].cond_setup_bindings.len);
            @memcpy(merged[0..cond_setup.len], cond_setup);
            @memcpy(merged[cond_setup.len..], inner[0].cond_setup_bindings);
            inner[0].cond_setup_bindings = merged;

            try branches.appendSlice(allocator, inner);
            return try branches.toOwnedSlice(allocator);
        },
        else => {},
    }

    // Otherwise, else branch should end with update_prop (final else)
    if (extractBranchUpdate(else_bindings)) |eu| {
        try branches.append(allocator, .{
            .cond_setup_bindings = &.{},
            .cond_ref = null,
            .prop_name = eu.prop_name,
            .value_bindings = eu.value_bindings,
            .value_ref = eu.value_ref,
        });
        return try branches.toOwnedSlice(allocator);
    }

    // Handle unreachable else: assert(false)
    if (isAssertFalseElse(else_bindings)) {
        return try branches.toOwnedSlice(allocator);
    }

    branches.deinit(allocator);
    return null;
}

/// Remap temp references in an ANF value according to a name mapping.
fn remapValueRefs(
    allocator: Allocator,
    value: ANFValue,
    name_map: *const std.StringHashMapUnmanaged([]const u8),
) LowerError!ANFValue {
    const r = struct {
        fn f(nm: *const std.StringHashMapUnmanaged([]const u8), s: []const u8) []const u8 {
            if (nm.get(s)) |mapped| return mapped;
            return s;
        }
    }.f;

    switch (value) {
        .load_param, .load_prop, .get_state_script => return value,
        .load_const => |lc| {
            switch (lc.value) {
                .string => |s| {
                    if (s.len > 5 and std.mem.startsWith(u8, s, "@ref:")) {
                        const target = s[5..];
                        if (name_map.get(target)) |mapped| {
                            const new_s = try std.fmt.allocPrint(allocator, "@ref:{s}", .{mapped});
                            return .{ .load_const = .{ .value = .{ .string = new_s } } };
                        }
                    }
                },
                else => {},
            }
            return value;
        },
        .bin_op => |bop| {
            return .{ .bin_op = .{
                .op = bop.op,
                .left = r(name_map, bop.left),
                .right = r(name_map, bop.right),
                .result_type = bop.result_type,
            } };
        },
        .unary_op => |uop| {
            return .{ .unary_op = .{
                .op = uop.op,
                .operand = r(name_map, uop.operand),
                .result_type = uop.result_type,
            } };
        },
        .call => |c| {
            const new_args = try allocator.alloc([]const u8, c.args.len);
            for (c.args, 0..) |a, i| new_args[i] = r(name_map, a);
            return .{ .call = .{ .func = c.func, .args = new_args } };
        },
        .method_call => |mc| {
            const new_args = try allocator.alloc([]const u8, mc.args.len);
            for (mc.args, 0..) |a, i| new_args[i] = r(name_map, a);
            return .{ .method_call = .{
                .object = r(name_map, mc.object),
                .method = mc.method,
                .args = new_args,
            } };
        },
        .assert => |a| {
            return .{ .assert = .{ .value = r(name_map, a.value) } };
        },
        .update_prop => |up| {
            return .{ .update_prop = .{ .name = up.name, .value = r(name_map, up.value) } };
        },
        .check_preimage => |cp| {
            return .{ .check_preimage = .{ .preimage = r(name_map, cp.preimage) } };
        },
        .deserialize_state => |ds| {
            return .{ .deserialize_state = .{ .preimage = r(name_map, ds.preimage) } };
        },
        .add_output => |ao| {
            const new_sv = try allocator.alloc([]const u8, ao.state_values.len);
            for (ao.state_values, 0..) |s, i| new_sv[i] = r(name_map, s);
            const new_sr = try allocator.alloc([]const u8, ao.state_refs.len);
            for (ao.state_refs, 0..) |s, i| new_sr[i] = r(name_map, s);
            return .{ .add_output = .{
                .satoshis = r(name_map, ao.satoshis),
                .state_values = new_sv,
                .preimage = if (ao.preimage.len > 0) r(name_map, ao.preimage) else ao.preimage,
                .state_refs = new_sr,
            } };
        },
        .add_raw_output => |aro| {
            return .{ .add_raw_output = .{
                .satoshis = r(name_map, aro.satoshis),
                .script_bytes = if (aro.script_bytes.len > 0) r(name_map, aro.script_bytes) else aro.script_bytes,
            } };
        },
        .add_data_output => |ado| {
            return .{ .add_data_output = .{
                .satoshis = r(name_map, ado.satoshis),
                .script_bytes = if (ado.script_bytes.len > 0) r(name_map, ado.script_bytes) else ado.script_bytes,
            } };
        },
        .@"if" => |ifv| {
            const new_if = try allocator.create(types.ANFIf);
            new_if.* = .{
                .cond = r(name_map, ifv.cond),
                .then = ifv.then,
                .@"else" = ifv.@"else",
            };
            return .{ .@"if" = new_if };
        },
        // F-003: explicit per-variant arms (no `else`) so adding a new
        // ANFValue variant fails at Zig compile time here instead of silently
        // skipping the rename and corrupting downstream IR. Mirrors the
        // `UnknownANFKindError` default in TS
        // `passes/04-anf-lower.ts#remapValueRefs`.
        .loop => return value,
        .array_literal => |al| {
            const new_elems = try allocator.alloc([]const u8, al.elements.len);
            for (al.elements, 0..) |e, i| new_elems[i] = r(name_map, e);
            return .{ .array_literal = .{ .elements = new_elems } };
        },
        .raw_script => return value,
    }
}

/// Transform if-bindings whose branches all end with update_prop into
/// flat conditional assignments.
fn liftBranchUpdateProps(
    allocator: Allocator,
    bindings: []const ANFBinding,
) LowerError![]ANFBinding {
    var next_idx: i64 = maxTempIndex(bindings) + 1;
    const FreshCtx = struct {
        allocator: Allocator,
        next_idx: *i64,
        fn fresh(self: @This()) LowerError![]const u8 {
            const name = try std.fmt.allocPrint(self.allocator, "t{d}", .{self.next_idx.*});
            self.next_idx.* += 1;
            return name;
        }
    };
    const fctx = FreshCtx{ .allocator = allocator, .next_idx = &next_idx };

    var result: std.ArrayListUnmanaged(ANFBinding) = .empty;

    for (bindings) |binding| {
        const if_val = switch (binding.value) {
            .@"if" => |v| v,
            else => {
                try result.append(allocator, binding);
                continue;
            },
        };

        const branches_maybe = try collectUpdateBranches(
            allocator,
            if_val.cond,
            stripDeclaredResults(if_val.then, if_val.results),
            stripDeclaredResults(if_val.@"else", if_val.results),
        );
        const branches = branches_maybe orelse {
            try result.append(allocator, binding);
            continue;
        };
        if (branches.len < 2) {
            try result.append(allocator, binding);
            continue;
        }

        // --- Transform: flatten into conditional assignments ---

        // 1. Hoist condition setup bindings with fresh names.
        var name_map: std.StringHashMapUnmanaged([]const u8) = .empty;
        defer name_map.deinit(allocator);

        var cond_refs: std.ArrayListUnmanaged(?[]const u8) = .empty;
        defer cond_refs.deinit(allocator);

        for (branches) |branch| {
            for (branch.cond_setup_bindings) |csb| {
                const new_name = try fctx.fresh();
                try name_map.put(allocator, csb.name, new_name);
                const remapped = try remapValueRefs(allocator, csb.value, &name_map);
                try result.append(allocator, .{
                    .name = new_name,
                    .value = remapped,
                });
            }
            if (branch.cond_ref) |cr| {
                const mapped: []const u8 = if (name_map.get(cr)) |m| m else cr;
                try cond_refs.append(allocator, mapped);
            } else {
                try cond_refs.append(allocator, null);
            }
        }

        // 2. Compute effective condition for each branch.
        var effective_conds: std.ArrayListUnmanaged([]const u8) = .empty;
        defer effective_conds.deinit(allocator);

        var negated_conds: std.ArrayListUnmanaged([]const u8) = .empty;
        defer negated_conds.deinit(allocator);

        for (branches, 0..) |_, i| {
            if (i == 0) {
                try effective_conds.append(allocator, cond_refs.items[0].?);
                continue;
            }

            // Negate any prior conditions not yet negated.
            var j: usize = negated_conds.items.len;
            while (j < i) : (j += 1) {
                const cr = cond_refs.items[j] orelse continue;
                const neg_name = try fctx.fresh();
                try result.append(allocator, .{
                    .name = neg_name,
                    .value = .{ .unary_op = .{ .op = "!", .operand = cr } },
                });
                try negated_conds.append(allocator, neg_name);
            }

            // AND all negated conditions together.
            var and_ref: []const u8 = negated_conds.items[0];
            const limit = if (negated_conds.items.len < i) negated_conds.items.len else i;
            var k: usize = 1;
            while (k < limit) : (k += 1) {
                const and_name = try fctx.fresh();
                try result.append(allocator, .{
                    .name = and_name,
                    .value = .{ .bin_op = .{
                        .op = "&&",
                        .left = and_ref,
                        .right = negated_conds.items[k],
                        .result_type = null,
                    } },
                });
                and_ref = and_name;
            }

            if (cond_refs.items[i]) |cr| {
                // Middle branch: AND with own condition.
                const final_name = try fctx.fresh();
                try result.append(allocator, .{
                    .name = final_name,
                    .value = .{ .bin_op = .{
                        .op = "&&",
                        .left = and_ref,
                        .right = cr,
                        .result_type = null,
                    } },
                });
                try effective_conds.append(allocator, final_name);
            } else {
                // Final else: just the AND of negations.
                try effective_conds.append(allocator, and_ref);
            }
        }

        // 2b. C20 — preserve a dropped terminal `assert(false)` else.
        //
        // `collectUpdateBranches` transforms a dispatch chain whose branches each
        // end in a single `update_prop` into this flat conditional-assignment form.
        // When the chain's terminal else is `assert(false)` it returns the branches
        // WITHOUT a catch-all final branch (every branch keeps a non-null cond_ref),
        // dropping the abort. But that assert(false) is the ONLY thing rejecting a
        // selector value that matches no branch: without it, an unmatched selector
        // leaves every property at its old value — a spendable NO-OP state
        // continuation instead of a failed script (a funds-safety bug).
        //
        // A real final else (`else { prop = ... }`) instead yields a catch-all
        // branch with cond_ref == null, and needs no guard because every selector
        // value maps to some branch. So the presence of a null-condRef terminal
        // branch exactly distinguishes the two cases.
        //
        // Re-introduce the abort as `assert(cond0 || cond1 || ... || cond_{N-1})`:
        // if no branch condition held, the OR is false and the script aborts —
        // byte-identical to the original `assert(false)` semantics for the
        // unmatched position, and a no-op (`assert(true)`) whenever a branch runs.
        const has_catch_all_else = cond_refs.items[cond_refs.items.len - 1] == null;
        if (!has_catch_all_else) {
            // Every branch here has a non-null cond_ref (only a catch-all final
            // else is null, and there is none), so the OR fully covers the
            // selector space.
            var or_ref: []const u8 = cond_refs.items[0].?;
            var i: usize = 1;
            while (i < cond_refs.items.len) : (i += 1) {
                const or_name = try fctx.fresh();
                try result.append(allocator, .{
                    .name = or_name,
                    .value = .{ .bin_op = .{
                        .op = "||",
                        .left = or_ref,
                        .right = cond_refs.items[i].?,
                        .result_type = null,
                    } },
                });
                or_ref = or_name;
            }
            try result.append(allocator, .{
                .name = try fctx.fresh(),
                .value = .{ .assert = .{ .value = or_ref } },
            });
        }

        // 3. For each branch, emit: load_old, conditional if-expression, update_prop.
        for (branches, 0..) |branch, i| {
            // Load old property value.
            const old_prop_ref = try fctx.fresh();
            try result.append(allocator, .{
                .name = old_prop_ref,
                .value = .{ .load_prop = .{ .name = branch.prop_name } },
            });

            // Remap value bindings for the then-branch.
            var branch_map: std.StringHashMapUnmanaged([]const u8) = .empty;
            defer branch_map.deinit(allocator);
            var map_it = name_map.iterator();
            while (map_it.next()) |entry| {
                try branch_map.put(allocator, entry.key_ptr.*, entry.value_ptr.*);
            }

            var then_bindings: std.ArrayListUnmanaged(ANFBinding) = .empty;
            for (branch.value_bindings) |vb| {
                const new_name = try fctx.fresh();
                try branch_map.put(allocator, vb.name, new_name);
                const remapped = try remapValueRefs(allocator, vb.value, &branch_map);
                try then_bindings.append(allocator, .{
                    .name = new_name,
                    .value = remapped,
                });
            }

            // Else branch: keep old property value.
            const keep_name = try fctx.fresh();
            var else_bindings_list: std.ArrayListUnmanaged(ANFBinding) = .empty;
            try else_bindings_list.append(allocator, .{
                .name = keep_name,
                .value = .{ .load_const = .{ .value = .{
                    .string = try std.fmt.allocPrint(allocator, "@ref:{s}", .{old_prop_ref}),
                } } },
            });

            // Emit conditional if-expression.
            const cond_if_ref = try fctx.fresh();
            const new_if = try allocator.create(types.ANFIf);
            new_if.* = .{
                .cond = effective_conds.items[i],
                .then = try then_bindings.toOwnedSlice(allocator),
                .@"else" = try else_bindings_list.toOwnedSlice(allocator),
            };
            try result.append(allocator, .{
                .name = cond_if_ref,
                .value = .{ .@"if" = new_if },
            });

            // Emit update_prop.
            const update_name = try fctx.fresh();
            try result.append(allocator, .{
                .name = update_name,
                .value = .{ .update_prop = .{
                    .name = branch.prop_name,
                    .value = cond_if_ref,
                } },
            });
        }
    }

    return try result.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "fresh temp names are sequential" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });

    const t0 = try ctx.freshTemp();
    defer allocator.free(t0);
    const t1 = try ctx.freshTemp();
    defer allocator.free(t1);
    const t2 = try ctx.freshTemp();
    defer allocator.free(t2);

    try std.testing.expectEqualStrings("t0", t0);
    try std.testing.expectEqualStrings("t1", t1);
    try std.testing.expectEqualStrings("t2", t2);
    try std.testing.expectEqual(@as(u32, 3), ctx.counter);
}

test "emit produces binding with correct name" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });

    const ref = try ctx.emit(makeLoadConstInt(42));
    defer allocator.free(ref);
    defer ctx.bindings.deinit(allocator);

    try std.testing.expectEqualStrings("t0", ref);
    try std.testing.expectEqual(@as(usize, 1), ctx.bindings.items.len);
    try std.testing.expectEqualStrings("t0", ctx.bindings.items[0].name);
}

test "lower literal int expression" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer ctx.bindings.deinit(allocator);

    const ref = try lowerExprToRef(&ctx, .{ .literal_int = 99 });
    defer allocator.free(ref);

    try std.testing.expectEqualStrings("t0", ref);
    try std.testing.expectEqual(@as(usize, 1), ctx.bindings.items.len);

    // Verify it's a load_const integer
    switch (ctx.bindings.items[0].value) {
        .load_const => |lc| {
            switch (lc.value) {
                .integer => |v| try std.testing.expectEqual(@as(i128, 99), v),
                else => return error.TestExpectedEqual,
            }
        },
        else => return error.TestExpectedEqual,
    }
}

test "lower binary expression flattens subexpressions" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer {
        for (ctx.bindings.items) |b| {
            switch (b.value) {
                .load_const, .bin_op => {},
                else => {},
            }
            allocator.free(b.name);
        }
        ctx.bindings.deinit(allocator);
    }

    // 1 + 2 should produce: t0 = load_const(1), t1 = load_const(2), t2 = bin_op(+, t0, t1)
    const bop = try allocator.create(types.BinaryOp);
    defer allocator.destroy(bop);
    bop.* = .{
        .op = .add,
        .left = .{ .literal_int = 1 },
        .right = .{ .literal_int = 2 },
    };

    const ref = try lowerExprToRef(&ctx, .{ .binary_op = bop });
    _ = ref;

    try std.testing.expectEqual(@as(usize, 3), ctx.bindings.items.len);
    try std.testing.expectEqualStrings("t0", ctx.bindings.items[0].name);
    try std.testing.expectEqualStrings("t1", ctx.bindings.items[1].name);
    try std.testing.expectEqualStrings("t2", ctx.bindings.items[2].name);

    // Verify the bin_op references t0 and t1
    switch (ctx.bindings.items[2].value) {
        .bin_op => |op| {
            try std.testing.expectEqualStrings("+", op.op);
            try std.testing.expectEqualStrings("t0", op.left);
            try std.testing.expectEqualStrings("t1", op.right);
        },
        else => return error.TestExpectedEqual,
    }
}

test "lower identifier as parameter" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer {
        for (ctx.bindings.items) |b| allocator.free(b.name);
        ctx.bindings.deinit(allocator);
    }

    // An unknown identifier is treated as a parameter
    const ref = try lowerExprToRef(&ctx, .{ .identifier = "pubKey" });
    _ = ref;

    try std.testing.expectEqual(@as(usize, 1), ctx.bindings.items.len);
    switch (ctx.bindings.items[0].value) {
        .load_param => |lp| try std.testing.expectEqualStrings("pubKey", lp.name),
        else => return error.TestExpectedEqual,
    }
}

test "lower property access" {
    const allocator = std.testing.allocator;

    const props = try allocator.alloc(PropertyNode, 1);
    defer allocator.free(props);
    props[0] = .{ .name = "pubKeyHash", .type_info = .ripemd160, .readonly = true };

    var ctx = LowerCtx.init(allocator, .{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = props,
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer {
        for (ctx.bindings.items) |b| allocator.free(b.name);
        ctx.bindings.deinit(allocator);
    }

    // this.pubKeyHash -> load_prop
    const ref = try lowerExprToRef(&ctx, .{ .property_access = .{ .object = "this", .property = "pubKeyHash" } });
    _ = ref;

    try std.testing.expectEqual(@as(usize, 1), ctx.bindings.items.len);
    switch (ctx.bindings.items[0].value) {
        .load_prop => |lp| try std.testing.expectEqualStrings("pubKeyHash", lp.name),
        else => return error.TestExpectedEqual,
    }
}

test "explicit this.x resolves to load_prop even when x is a registered param (#130)" {
    const allocator = std.testing.allocator;

    const props = try allocator.alloc(PropertyNode, 1);
    defer allocator.free(props);
    props[0] = .{ .name = "balance", .type_info = .bigint, .readonly = false };

    var ctx = LowerCtx.init(allocator, .{
        .name = "ShadowRepro",
        .parent_class = .stateful_smart_contract,
        .properties = props,
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer {
        for (ctx.bindings.items) |b| allocator.free(b.name);
        ctx.bindings.deinit(allocator);
        ctx.param_names.deinit(allocator);
    }

    // A method param named `balance` shadows the mutable property `balance`.
    ctx.addParam("balance");

    // Bare identifier `balance` -> load_param (the witness value).
    const id_ref = try lowerIdentifier(&ctx, "balance");
    _ = id_ref;
    switch (ctx.bindings.items[0].value) {
        .load_param => |lp| try std.testing.expectEqualStrings("balance", lp.name),
        else => return error.TestExpectedLoadParam,
    }

    // Explicit `this.balance` -> load_prop (the property always wins).
    const prop_ref = try lowerExprToRef(&ctx, .{ .property_access = .{ .object = "this", .property = "balance" } });
    _ = prop_ref;
    switch (ctx.bindings.items[1].value) {
        .load_prop => |lp| try std.testing.expectEqualStrings("balance", lp.name),
        else => return error.TestExpectedLoadProp,
    }
}

test "lower assert expression" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer {
        for (ctx.bindings.items) |b| allocator.free(b.name);
        ctx.bindings.deinit(allocator);
    }

    // assert(true) -> t0 = load_const(true), t1 = assert(t0)
    const assert_args = try allocator.alloc(Expression, 1);
    defer allocator.free(assert_args);
    assert_args[0] = .{ .literal_bool = true };

    const call = try allocator.create(types.CallExpr);
    defer allocator.destroy(call);
    call.* = .{ .callee = "assert", .args = assert_args };

    const ref = try lowerExprToRef(&ctx, .{ .call = call });
    _ = ref;

    try std.testing.expectEqual(@as(usize, 2), ctx.bindings.items.len);
    // First binding: load_const(true)
    switch (ctx.bindings.items[0].value) {
        .load_const => |lc| {
            switch (lc.value) {
                .boolean => |v| try std.testing.expect(v),
                else => return error.TestExpectedEqual,
            }
        },
        else => return error.TestExpectedEqual,
    }
    // Second binding: assert(t0)
    switch (ctx.bindings.items[1].value) {
        .assert => |a| try std.testing.expectEqualStrings("t0", a.value),
        else => return error.TestExpectedEqual,
    }
}

test "P2PKH contract full lowering" {
    const allocator = std.testing.allocator;

    // Build a P2PKH contract AST:
    //   contract P2PKH extends SmartContract {
    //     readonly pubKeyHash: Addr;
    //     constructor(pubKeyHash: Addr) { super(pubKeyHash); }
    //     public unlock(sig: Sig, pubKey: PubKey) {
    //       assert(hash160(pubKey) === this.pubKeyHash);
    //       assert(checkSig(sig, pubKey));
    //     }
    //   }

    // Properties
    const props = try allocator.alloc(PropertyNode, 1);
    defer allocator.free(props);
    props[0] = .{ .name = "pubKeyHash", .type_info = .ripemd160, .readonly = true };

    // Constructor
    const ctor_params = try allocator.alloc(ParamNode, 1);
    defer allocator.free(ctor_params);
    ctor_params[0] = .{ .name = "pubKeyHash", .type_info = .ripemd160, .type_name = "Addr" };

    const ctor_assignments = try allocator.alloc(types.AssignmentNode, 1);
    defer allocator.free(ctor_assignments);
    ctor_assignments[0] = .{ .target = "pubKeyHash", .value = .{ .identifier = "pubKeyHash" } };

    // Method body: two assert statements
    // Statement 1: assert(hash160(pubKey) === this.pubKeyHash)
    const hash_args = try allocator.alloc(Expression, 1);
    defer allocator.free(hash_args);
    hash_args[0] = .{ .identifier = "pubKey" };
    const hash_call = try allocator.create(types.CallExpr);
    defer allocator.destroy(hash_call);
    hash_call.* = .{ .callee = "hash160", .args = hash_args };

    const eq_op = try allocator.create(types.BinaryOp);
    defer allocator.destroy(eq_op);
    eq_op.* = .{
        .op = .eq,
        .left = .{ .call = hash_call },
        .right = .{ .property_access = .{ .object = "this", .property = "pubKeyHash" } },
    };

    const assert1_args = try allocator.alloc(Expression, 1);
    defer allocator.free(assert1_args);
    assert1_args[0] = .{ .binary_op = eq_op };
    const assert1_call = try allocator.create(types.CallExpr);
    defer allocator.destroy(assert1_call);
    assert1_call.* = .{ .callee = "assert", .args = assert1_args };

    // Statement 2: assert(checkSig(sig, pubKey))
    const check_args = try allocator.alloc(Expression, 2);
    defer allocator.free(check_args);
    check_args[0] = .{ .identifier = "sig" };
    check_args[1] = .{ .identifier = "pubKey" };
    const check_call = try allocator.create(types.CallExpr);
    defer allocator.destroy(check_call);
    check_call.* = .{ .callee = "checkSig", .args = check_args };

    const assert2_args = try allocator.alloc(Expression, 1);
    defer allocator.free(assert2_args);
    assert2_args[0] = .{ .call = check_call };
    const assert2_call = try allocator.create(types.CallExpr);
    defer allocator.destroy(assert2_call);
    assert2_call.* = .{ .callee = "assert", .args = assert2_args };

    // Build method body as statement slice
    const body = try allocator.alloc(Statement, 2);
    defer allocator.free(body);
    body[0] = .{ .expr_stmt = .{ .expr = .{ .call = assert1_call } } };
    body[1] = .{ .expr_stmt = .{ .expr = .{ .call = assert2_call } } };

    // Method params
    const method_params = try allocator.alloc(ParamNode, 2);
    defer allocator.free(method_params);
    method_params[0] = .{ .name = "sig", .type_info = .sig, .type_name = "Sig" };
    method_params[1] = .{ .name = "pubKey", .type_info = .pub_key, .type_name = "PubKey" };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "unlock", .is_public = true, .params = method_params, .body = body };

    const contract = ContractNode{
        .name = "P2PKH",
        .parent_class = .smart_contract,
        .properties = props,
        .constructor = .{ .params = ctor_params, .super_args = &.{}, .assignments = ctor_assignments },
        .methods = methods,
    };

    const program = try lowerToANF(allocator, contract);

    // Free all allocated temp names and nested structures
    defer {
        for (program.methods) |m| {
            for (m.bindings) |b| {
                // Free temp names (t0, t1, ...) and @ref: strings
                if (b.name.len >= 2 and b.name[0] == 't') {
                    allocator.free(b.name);
                }
                // Free nested allocations in values
                switch (b.value) {
                    .load_const => |lc| {
                        switch (lc.value) {
                            .string => |s| {
                                if (s.len > 5 and std.mem.startsWith(u8, s, "@ref:")) {
                                    allocator.free(s);
                                }
                            },
                            else => {},
                        }
                    },
                    .call => |c| {
                        if (c.args.len > 0) allocator.free(c.args);
                    },
                    else => {},
                }
            }
            if (m.bindings.len > 0) allocator.free(m.bindings);
        }
        allocator.free(program.methods);
        allocator.free(program.properties);
    }

    // Validate structure
    try std.testing.expectEqualStrings("P2PKH", program.contract_name);
    try std.testing.expectEqual(@as(usize, 1), program.properties.len);
    try std.testing.expectEqualStrings("pubKeyHash", program.properties[0].name);
    try std.testing.expect(program.properties[0].readonly);

    // Should have 2 methods: constructor + unlock
    try std.testing.expectEqual(@as(usize, 2), program.methods.len);
    try std.testing.expectEqualStrings("constructor", program.methods[0].name);
    try std.testing.expectEqualStrings("unlock", program.methods[1].name);
    try std.testing.expect(program.methods[1].is_public);

    // Constructor should have 1 assignment binding (update_prop)
    const ctor_bindings = program.methods[0].bindings;
    try std.testing.expect(ctor_bindings.len >= 1);

    // Unlock method body should have bindings for the P2PKH logic:
    //   t0 = load_param("pubKey")
    //   t1 = call("hash160", [t0])
    //   t2 = load_prop("pubKeyHash")
    //   t3 = bin_op("===", t1, t2, result_type="bytes")
    //   t4 = assert(t3)
    //   t5 = load_param("sig")
    //   t6 = load_param("pubKey")
    //   t7 = call("checkSig", [t5, t6])
    //   t8 = assert(t7)
    const unlock_bindings = program.methods[1].bindings;
    try std.testing.expect(unlock_bindings.len >= 9);

    // Verify first binding is load_param("pubKey")
    switch (unlock_bindings[0].value) {
        .load_param => |lp| try std.testing.expectEqualStrings("pubKey", lp.name),
        else => return error.TestExpectedEqual,
    }

    // Verify second binding is call("hash160", ...)
    switch (unlock_bindings[1].value) {
        .call => |c| try std.testing.expectEqualStrings("hash160", c.func),
        else => return error.TestExpectedEqual,
    }

    // Verify third binding is load_prop("pubKeyHash")
    switch (unlock_bindings[2].value) {
        .load_prop => |lp| try std.testing.expectEqualStrings("pubKeyHash", lp.name),
        else => return error.TestExpectedEqual,
    }

    // Verify fourth binding is bin_op("===", ...) with bytes result type
    switch (unlock_bindings[3].value) {
        .bin_op => |op| {
            try std.testing.expectEqualStrings("===", op.op);
            try std.testing.expectEqualStrings("t1", op.left);
            try std.testing.expectEqualStrings("t2", op.right);
            if (op.result_type) |rt| {
                try std.testing.expectEqualStrings("bytes", rt);
            } else {
                return error.TestExpectedEqual;
            }
        },
        else => return error.TestExpectedEqual,
    }

    // Verify fifth binding is assert
    switch (unlock_bindings[4].value) {
        .assert => |a| try std.testing.expectEqualStrings("t3", a.value),
        else => return error.TestExpectedEqual,
    }
}

test "stateful contract injects checkPreimage at public method entry" {
    // GAP-m6: a public method of a StatefulSmartContract must have the
    // compiler auto-inject `checkPreimage(txPreimage)` as the first three
    // bindings: load_param("txPreimage") -> check_preimage -> assert.
    const allocator = std.testing.allocator;

    // contract Counter extends StatefulSmartContract {
    //   count: bigint;                       // mutable state
    //   constructor(count: bigint) { super(count); }
    //   public touch() { assert(1); }
    // }
    const props = try allocator.alloc(PropertyNode, 1);
    defer allocator.free(props);
    props[0] = .{ .name = "count", .type_info = .bigint, .readonly = false };

    const ctor_params = try allocator.alloc(ParamNode, 1);
    defer allocator.free(ctor_params);
    ctor_params[0] = .{ .name = "count", .type_info = .bigint, .type_name = "bigint" };

    const ctor_assignments = try allocator.alloc(types.AssignmentNode, 1);
    defer allocator.free(ctor_assignments);
    ctor_assignments[0] = .{ .target = "count", .value = .{ .identifier = "count" } };

    // Method body: assert(1) — a trivial public spend path. The body content
    // is irrelevant; what matters is that checkPreimage is injected ahead of it.
    const assert_args = try allocator.alloc(Expression, 1);
    defer allocator.free(assert_args);
    assert_args[0] = .{ .literal_int = 1 };
    const assert_call = try allocator.create(types.CallExpr);
    defer allocator.destroy(assert_call);
    assert_call.* = .{ .callee = "assert", .args = assert_args };

    const body = try allocator.alloc(Statement, 1);
    defer allocator.free(body);
    body[0] = .{ .expr_stmt = .{ .expr = .{ .call = assert_call } } };

    const methods = try allocator.alloc(MethodNode, 1);
    defer allocator.free(methods);
    methods[0] = .{ .name = "touch", .is_public = true, .params = &.{}, .body = body };

    const contract = ContractNode{
        .name = "Counter",
        .parent_class = .stateful_smart_contract,
        .properties = props,
        .constructor = .{ .params = ctor_params, .super_args = &.{}, .assignments = ctor_assignments },
        .methods = methods,
    };

    const program = try lowerToANF(allocator, contract);
    defer {
        for (program.methods) |m| {
            for (m.bindings) |b| {
                if (b.name.len >= 2 and b.name[0] == 't') allocator.free(b.name);
                switch (b.value) {
                    .call => |c| if (c.args.len > 0) allocator.free(c.args),
                    else => {},
                }
            }
            if (m.bindings.len > 0) allocator.free(m.bindings);
        }
        // The public stateful method (`touch`, index 1) has an augmented
        // params slice freshly allocated by lowerMethods (original params +
        // implicit txPreimage / change-output params). The constructor's
        // params alias `contract.constructor.params` and must not be freed here.
        allocator.free(program.methods[1].params);
        allocator.free(program.methods);
        allocator.free(program.properties);
    }

    // methods = [constructor, touch]
    try std.testing.expectEqual(@as(usize, 2), program.methods.len);
    try std.testing.expectEqualStrings("touch", program.methods[1].name);
    try std.testing.expect(program.methods[1].is_public);

    const touch_bindings = program.methods[1].bindings;
    try std.testing.expect(touch_bindings.len >= 3);

    // Binding 0: load_param("txPreimage")
    switch (touch_bindings[0].value) {
        .load_param => |lp| try std.testing.expectEqualStrings("txPreimage", lp.name),
        else => return error.TestExpectedEqual,
    }
    // Binding 1: check_preimage over that param
    switch (touch_bindings[1].value) {
        .check_preimage => |cp| try std.testing.expectEqualStrings(touch_bindings[0].name, cp.preimage),
        else => return error.TestExpectedEqual,
    }
    // Binding 2: assert over the check_preimage result
    switch (touch_bindings[2].value) {
        .assert => |a| try std.testing.expectEqualStrings(touch_bindings[1].name, a.value),
        else => return error.TestExpectedEqual,
    }
}

test "sub_context shares counter" {
    const allocator = std.testing.allocator;
    var ctx = LowerCtx.init(allocator, .{
        .name = "Test",
        .parent_class = .smart_contract,
        .properties = &.{},
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });

    // Emit a few temps
    const t0 = try ctx.freshTemp();
    defer allocator.free(t0);
    const t1 = try ctx.freshTemp();
    defer allocator.free(t1);

    try std.testing.expectEqual(@as(u32, 2), ctx.counter);

    // Sub-context starts where parent left off
    var sub = ctx.subContext();
    const t2 = try sub.freshTemp();
    defer allocator.free(t2);

    try std.testing.expectEqualStrings("t2", t2);
    try std.testing.expectEqual(@as(u32, 3), sub.counter);

    // Sync back
    ctx.syncCounter(&sub);
    try std.testing.expectEqual(@as(u32, 3), ctx.counter);
}

test "extractLiteralValue handles all literal types" {
    // Integer
    const int_val = extractLiteralValue(.{ .literal_int = 42 });
    try std.testing.expect(int_val != null);
    switch (int_val.?) {
        .integer => |v| try std.testing.expectEqual(@as(i128, 42), v),
        else => return error.TestExpectedEqual,
    }

    // Boolean
    const bool_val = extractLiteralValue(.{ .literal_bool = true });
    try std.testing.expect(bool_val != null);
    switch (bool_val.?) {
        .boolean => |v| try std.testing.expect(v),
        else => return error.TestExpectedEqual,
    }

    // Bytes
    const bytes_val = extractLiteralValue(.{ .literal_bytes = "deadbeef" });
    try std.testing.expect(bytes_val != null);
    switch (bytes_val.?) {
        .string => |v| try std.testing.expectEqualStrings("deadbeef", v),
        else => return error.TestExpectedEqual,
    }

    // Unsupported
    const none_val = extractLiteralValue(.{ .identifier = "x" });
    try std.testing.expect(none_val == null);
}

test "isByteReturningFunction" {
    try std.testing.expect(isByteReturningFunction("sha256"));
    try std.testing.expect(isByteReturningFunction("hash160"));
    try std.testing.expect(isByteReturningFunction("ripemd160"));
    try std.testing.expect(isByteReturningFunction("cat"));
    try std.testing.expect(!isByteReturningFunction("checkSig"));
    try std.testing.expect(!isByteReturningFunction("add"));
}

test "isByteType" {
    try std.testing.expect(isByteType(.byte_string));
    try std.testing.expect(isByteType(.pub_key));
    try std.testing.expect(isByteType(.sig));
    try std.testing.expect(isByteType(.ripemd160));
    try std.testing.expect(!isByteType(.bigint));
    try std.testing.expect(!isByteType(.boolean));
}

test "branchEndsWithReturn" {
    // Empty body
    try std.testing.expect(!branchEndsWithReturn(&.{}));

    // Body ending with return
    const stmts_ret = [_]Statement{.{ .return_stmt = .{ .literal_int = 1 } }};
    try std.testing.expect(branchEndsWithReturn(&stmts_ret));

    // Body ending with non-return
    const stmts_no_ret = [_]Statement{.{ .expr_stmt = .{ .expr = .{ .literal_int = 1 } } }};
    try std.testing.expect(!branchEndsWithReturn(&stmts_no_ret));
}

test "lower properties with initial values" {
    const allocator = std.testing.allocator;

    const props = try allocator.alloc(PropertyNode, 2);
    defer allocator.free(props);
    props[0] = .{ .name = "counter", .type_info = .bigint, .readonly = false, .initializer = .{ .literal_int = 0 } };
    props[1] = .{ .name = "owner", .type_info = .ripemd160, .readonly = true };

    const result = try lowerProperties(allocator, .{
        .name = "Test",
        .parent_class = .stateful_smart_contract,
        .properties = props,
        .constructor = .{ .params = &.{}, .super_args = &.{}, .assignments = &.{} },
        .methods = &.{},
    });
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("counter", result[0].name);
    try std.testing.expect(!result[0].readonly);
    try std.testing.expect(result[0].initial_value != null);
    switch (result[0].initial_value.?) {
        .integer => |v| try std.testing.expectEqual(@as(i128, 0), v),
        else => return error.TestExpectedEqual,
    }
    try std.testing.expectEqualStrings("owner", result[1].name);
    try std.testing.expect(result[1].readonly);
    try std.testing.expect(result[1].initial_value == null);
}

// -- #121: lowerForStatement resolves the compile-time loop shape (start / step
// / count) for non-zero-start and countdown loops. Uses an arena so all
// allocations are freed together.

/// Find method "m"'s loop node and return it (or null).
fn findLoweredLoop(program: ANFProgram) ?types.ANFLoop {
    for (program.methods) |m| {
        if (!std.mem.eql(u8, m.name, "m")) continue;
        for (m.bindings) |b| {
            switch (b.value) {
                .loop => |lp| return lp.*,
                else => {},
            }
        }
    }
    return null;
}

fn lowerContractWithLoop(alloc: Allocator, for_stmt: types.ForStmt) LowerError!ANFProgram {
    const props = try alloc.alloc(PropertyNode, 1);
    props[0] = .{ .name = "x", .type_info = .bigint, .readonly = true };

    const ctor_params = try alloc.alloc(ParamNode, 1);
    ctor_params[0] = .{ .name = "x", .type_info = .bigint, .type_name = "bigint" };
    const ctor_assignments = try alloc.alloc(types.AssignmentNode, 1);
    ctor_assignments[0] = .{ .target = "x", .value = .{ .identifier = "x" } };

    const body = try alloc.alloc(Statement, 2);
    body[0] = .{ .for_stmt = for_stmt };
    body[1] = .{ .assert_stmt = .{ .condition = .{ .literal_bool = true } } };

    const methods = try alloc.alloc(MethodNode, 1);
    methods[0] = .{ .name = "m", .is_public = true, .params = &.{}, .body = body };

    return lowerToANF(alloc, .{
        .name = "C",
        .parent_class = .smart_contract,
        .properties = props,
        .constructor = .{ .params = ctor_params, .super_args = &.{}, .assignments = ctor_assignments },
        .methods = methods,
    });
}

test "lowering supports a countdown loop (#121)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // for (let i = 3; i > 0; i--)  -> start 3, step -1, count 3
    const for_stmt = types.ForStmt{ .var_name = "i", .init_value = 3, .bound = 0, .descending = true, .body = &.{} };
    const program = try lowerContractWithLoop(arena.allocator(), for_stmt);
    const lp = findLoweredLoop(program) orelse return error.TestExpectedLoop;
    try std.testing.expectEqual(@as(u32, 3), lp.count);
    try std.testing.expectEqual(@as(i64, 3), lp.start);
    try std.testing.expectEqual(@as(i8, -1), lp.step);
}

test "lowering supports a non-zero-start loop (#121)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // for (let i = 1; i <= 3; i++)  -> start 1, step +1, count 3
    const for_stmt = types.ForStmt{ .var_name = "i", .init_value = 1, .bound = 3, .inclusive = true, .body = &.{} };
    const program = try lowerContractWithLoop(arena.allocator(), for_stmt);
    const lp = findLoweredLoop(program) orelse return error.TestExpectedLoop;
    try std.testing.expectEqual(@as(u32, 3), lp.count);
    try std.testing.expectEqual(@as(i64, 1), lp.start);
    try std.testing.expectEqual(@as(i8, 1), lp.step);
}

test "lowering still accepts a zero-start counting-up loop" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // for (let i = 0; i < 4; i++)
    const for_stmt = types.ForStmt{ .var_name = "i", .init_value = 0, .bound = 4, .body = &.{} };
    const program = try lowerContractWithLoop(arena.allocator(), for_stmt);
    // Find method "m" and confirm it lowered a loop with count 4.
    var found_loop = false;
    for (program.methods) |m| {
        if (!std.mem.eql(u8, m.name, "m")) continue;
        for (m.bindings) |b| {
            switch (b.value) {
                .loop => |lp| {
                    found_loop = true;
                    try std.testing.expectEqual(@as(u32, 4), lp.count);
                },
                else => {},
            }
        }
    }
    try std.testing.expect(found_loop);
}
