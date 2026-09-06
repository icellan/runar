//! Pass 4: ANF Lower
//!
//! Lowers the Rúnar AST to A-Normal Form (ANF) IR. This is the critical
//! transformation pass -- it flattens all nested expressions into a sequence
//! of let-bindings where every right-hand side is a simple value.
//!
//! Example:
//!   assert(checkSig(sig, this.pk))
//! becomes:
//!   let t0 = load_param("sig")
//!   let t1 = load_prop("pk")
//!   let t2 = call("checkSig", [t0, t1])
//!   let t3 = assert(t2)
//!
//! This matches the TypeScript reference compiler's 04-anf-lower.ts exactly.
//! Key design decisions:
//! - No parameter pre-loading (params are loaded lazily on first reference)
//! - addParam is never called (matching TS where addParam exists but is unused)
//! - Local variables are tracked via localNames set
//! - Properties are checked against the contract

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use super::ast::*;
use super::sighash_directive::SIGHASH_DEFAULT;
use super::side_effect_summary::{
    compute_side_effect_summary, ContinuationShape, SideEffectSummary,
};
use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFProperty, ANFSyntheticArrayLevel, ANFValue, SourceLocation, MERGED_LOCAL_TEMP_PREFIX};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Lower a type-checked Rúnar AST to ANF IR.
pub fn lower_to_anf(contract: &ContractNode) -> ANFProgram {
    let properties = lower_properties(contract);
    let mut methods = lower_methods(contract);

    // Post-process: lift nested if-else chains with update_prop into flat
    // conditional assignments. This matches the TS reference compiler's
    // liftBranchUpdateProps transformation (04-anf-lower.ts line 50).
    for method in &mut methods {
        method.body = lift_branch_update_props(method.body.clone());
    }

    ANFProgram {
        contract_name: contract.name.clone(),
        properties,
        methods,
        parent_class: contract.parent_class.clone(),
    }
}

/// Lower a type-checked Rúnar AST to ANF IR, converting a panic into a proper
/// error return instead of unwinding out of the compiler.
///
/// Pass 4 panics deliberately: it is how the lowering pass refuses a construct
/// it must not emit (e.g. a conditional that both declares outputs and merges
/// two or more locals, which used to compile to an unspendable script). This
/// is the same wrapper the backend uses for pass 5 — see
/// `codegen::stack::lower_to_stack` around `lower_to_stack_inner`.
pub fn try_lower_to_anf(contract: &ContractNode) -> Result<ANFProgram, String> {
    crate::refusal::catch_refusal("anf lowering", || lower_to_anf(contract))
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

fn lower_properties(contract: &ContractNode) -> Vec<ANFProperty> {
    contract
        .properties
        .iter()
        .map(|prop| {
            let prop_type = type_node_to_string(&prop.prop_type);
            check_state_bigint_magnitude(prop, &prop_type);
            ANFProperty {
                name: prop.name.clone(),
                prop_type,
                readonly: prop.readonly,
                initial_value: prop.initializer.as_ref().and_then(extract_literal_value),
                synthetic_array_chain: prop.synthetic_array_chain.as_ref().map(|chain| {
                    chain
                        .iter()
                        .map(|level| ANFSyntheticArrayLevel {
                            base: level.base.clone(),
                            index: level.index,
                            length: level.length,
                        })
                        .collect()
                }),
            }
        })
        .collect()
}

/// Reject a MUTABLE bigint property initialised beyond the 8-byte state word.
///
/// `num2bin-le8` is a fixed 8-byte little-endian SIGN-MAGNITUDE word: bytes
/// 0..6 plus the low 7 bits of byte 7 carry the magnitude, 0x80 of byte 7
/// carries the sign. A magnitude of 2^63 or more does not fit, and nothing
/// used to check: the compiler stamped `encoding: "num2bin-le8"` on the field
/// and carried the initializer verbatim, the SDK wrote the low 8 bytes of it
/// into the deployed state section, and the covenant then rebuilt the
/// continuation with its own OP_NUM2BIN 8 — which produces different bytes —
/// so hash256(outputs) never matched and the UTXO was permanently unspendable.
/// It deployed cleanly, with no diagnostic at compile time or deploy time.
///
/// This catches the statically-known half. Values that only exist at call time
/// are stopped by the SDK serializer (packages/runar-rs/src/sdk/state.rs).
///
/// READONLY properties are deliberately exempt: they are baked into the
/// locking script as script-number pushes, never into the state section, and
/// BSV script numbers are arbitrary-precision after Genesis.
fn check_state_bigint_magnitude(prop: &PropertyNode, prop_type: &str) {
    if prop.readonly || (prop_type != "bigint" && prop_type != "int") {
        return;
    }
    let Some(value) = prop.initializer.as_ref().and_then(literal_bigint) else {
        return;
    };
    let limit = num_bigint::BigInt::from(1u8) << 63u32;
    let neg_limit = -limit.clone();
    if value < limit && value > neg_limit {
        return;
    }
    panic!(
        "Cannot compile state property '{}' initialised to {}: it does not fit \
         the fixed 8-byte sign-magnitude state word (magnitude must be < 2^63). \
         Reduce the value, or make the property readonly if it is a constant \
         rather than state.",
        prop.name, value,
    );
}

/// The signed value of a bigint literal (with an optional unary minus), or
/// `None` for any other initializer form.
fn literal_bigint(expr: &Expression) -> Option<num_bigint::BigInt> {
    match expr {
        Expression::BigIntLiteral { value } => Some(value.clone()),
        Expression::UnaryExpr {
            op: UnaryOp::Neg,
            operand,
        } => match operand.as_ref() {
            Expression::BigIntLiteral { value } => Some(-value),
            _ => None,
        },
        _ => None,
    }
}

/// Convert an i128 to a serde_json::Value. Values within i64 range use
/// Number; larger values fall back to a JSON number via string parsing so
/// precision is preserved in the IR.

/// Serialise a `num_bigint::BigInt` to a `serde_json::Value` for IR-JSON.
///
/// Values a bare JSON number carries losslessly — magnitude at most
/// `Number.MAX_SAFE_INTEGER` — serialise as JSON numbers. Larger values
/// serialise as a JS-style decimal `BigInt` literal — the decimal digits
/// followed by a literal `n` suffix, quoted as a JSON string. The `n`
/// suffix is the cross-tier discriminator that distinguishes a decimal
/// `BigInt` from a hex-encoded `ByteString` literal (both are JSON
/// strings made of ASCII digits in the all-decimal case, e.g. `"3030"`
/// is both a valid decimal and a valid hex bytestring).
///
/// `i64` is NOT the boundary: a bare JSON number is decoded into an
/// IEEE-754 double by every JS consumer (and by Go's `encoding/json`
/// when the target is `interface{}`), so `9007199254740993` — well
/// inside `i64` — comes back as `9007199254740992`.
///
/// Mirrors:
///   - Go: `compilers/go/ir/types.go::BigIntToRawJSON`
///   - Python: `compilers/python/runar_compiler/frontend/anf_lower.py::_make_load_const_int`
///   - TS: `conformance/runner/runner.ts` BigInt canonicalisation
pub(crate) fn bigint_to_json(v: &num_bigint::BigInt) -> serde_json::Value {
    use num_traits::ToPrimitive;
    match v.to_i64() {
        Some(i) if i.unsigned_abs() <= JS_MAX_SAFE_INTEGER => {
            serde_json::Value::Number(serde_json::Number::from(i))
        }
        _ => serde_json::Value::String(format!("{}n", v)),
    }
}

/// `Number.MAX_SAFE_INTEGER` (2^53 - 1).
pub(crate) const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Mirrors `flattenAddOutputArgs` in `04-anf-lower.ts`: when
/// `this.addOutput` is called as `this.addOutput(satoshis, .{ v1, v2, ... })`
/// (the surface form Zig / Move tuple syntax produce), unwrap the trailing
/// array literal so each element becomes an individual state value.
fn flatten_add_output_args(args: &[Expression]) -> Vec<Expression> {
    if args.len() == 2 {
        if let Expression::ArrayLiteral { elements } = &args[1] {
            let mut out = Vec::with_capacity(1 + elements.len());
            out.push(args[0].clone());
            for el in elements {
                out.push(el.clone());
            }
            return out;
        }
    }
    args.to_vec()
}

fn extract_literal_value(expr: &Expression) -> Option<serde_json::Value> {
    match expr {
        Expression::BigIntLiteral { value } => Some(bigint_to_json(value)),
        Expression::BoolLiteral { value } => Some(serde_json::Value::Bool(*value)),
        Expression::ByteStringLiteral { value } => {
            Some(serde_json::Value::String(value.clone()))
        }
        Expression::UnaryExpr {
            op: UnaryOp::Neg,
            operand,
        } => {
            if let Expression::BigIntLiteral { value } = operand.as_ref() {
                Some(bigint_to_json(&(-value)))
            } else {
                None
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

fn lower_methods(contract: &ContractNode) -> Vec<ANFMethod> {
    let mut result = Vec::new();

    // Single source of truth for "does this method (transitively) mutate
    // state, emit outputs, or use the preimage?" Shared across the
    // lowering pass so every public method's auto-injection sees
    // private-helper effects, not just direct ones.
    let side_effects = compute_side_effect_summary(contract);

    // Issue #109: readonly fields carrying a `/** @embedAlways */` directive
    // must survive DCE into the locking script. A readonly field no method
    // references lowers to no `load_prop`, so no constructor slot is emitted
    // and the field's deploy-time bytes vanish. We inject a `load_prop` + a
    // `@ref:` alias (the exact shape `const _bind = this.field;` produces) into
    // the first public method's body — the alias keeps the `load_prop` alive
    // through dead-binding DCE, and stack lowering threads the pushed value
    // through and NIPs it at method end. One slot in the deployed script
    // suffices; every spending branch shares it.
    let embed_fields: Vec<&PropertyNode> = contract
        .properties
        .iter()
        .filter(|p| p.readonly && p.embed_always)
        .collect();
    let mut embed_injected = false;

    // Lower constructor (the TS reference includes the constructor in output)
    let mut ctor_ctx = LoweringContext::with_effects(contract, Some(side_effects.clone()));
    for p in &contract.constructor.params {
        ctor_ctx.register_param_type(&p.name, &type_node_to_string(&p.param_type));
    }
    lower_statements(&contract.constructor.body, &mut ctor_ctx);
    result.push(ANFMethod {
        name: "constructor".to_string(),
        params: lower_params(&contract.constructor.params),
        body: ctor_ctx.bindings,
        is_public: false,
        sighash_type: None,
    });

    // Lower each method (including private methods as separate entries)
    for method in &contract.methods {
        let mut method_ctx = LoweringContext::with_effects(contract, Some(side_effects.clone()));
        // Issue #123: a non-default @sighash mode drives the OP_PUSH_TX binding
        // flag for any checkPreimage (auto-injected below, or a manual call) in
        // this method. Default ALL|FORKID leaves the flag `None` so the pinned
        // binding blob is unchanged.
        if let Some(v) = method.sighash_type {
            if v != SIGHASH_DEFAULT {
                method_ctx.sighash_flag = Some(v);
            }
        }
        // Register THIS method's declared params for method-scoped byte-type
        // analysis (issue #34). Auto-injected continuation params register
        // their types below, next to their add_param calls.
        for p in &method.params {
            method_ctx.register_param_type(&p.name, &type_node_to_string(&p.param_type));
        }

        // Register the declared param NAMES so a bare identifier resolves to
        // `load_param` before falling through to `load_prop` (issue #130).
        // Without this, a param whose name collides with a mutable state
        // property lowered to the stale deserialized property value instead of
        // the witness param. Explicit `this.x` is unaffected: it checks
        // is_property before is_param (see PropertyAccess / lower_member_expr).
        for p in &method.params {
            method_ctx.add_param(&p.name);
        }

        if contract.parent_class == "StatefulSmartContract"
            && method.visibility == Visibility::Public
        {
            // Continuation requirements come from the side-effect
            // summary, which walks the private-method call graph. A
            // public method that calls a private helper which mutates
            // state or emits an output must therefore inject the same
            // continuation params as if the public body did so
            // directly.
            let eff = side_effects
                .get(&method.name)
                .copied()
                .unwrap_or_default();
            let shape = ContinuationShape::for_effects(&eff);
            let needs_change_output = shape.needs_change;
            let needs_new_amount = shape.needs_new_amount;

            // Register implicit parameters
            if needs_change_output {
                method_ctx.add_param("_changePKH");
                method_ctx.register_param_type("_changePKH", "Ripemd160");
                method_ctx.add_param("_changeAmount");
                method_ctx.register_param_type("_changeAmount", "bigint");
            }
            if needs_new_amount {
                method_ctx.add_param("_newAmount");
                method_ctx.register_param_type("_newAmount", "bigint");
            }
            method_ctx.add_param("txPreimage");
            method_ctx.register_param_type("txPreimage", "SigHashPreimage");

            // Issue #123: the declared per-method sighash mode (default
            // ALL|FORKID). Drives BOTH the OP_PUSH_TX binding flag (so the
            // derived sig re-computes the tx sighash under this mode) AND the
            // runtime preimage-type assert.
            let sighash_mode = method.sighash_type.unwrap_or(SIGHASH_DEFAULT);

            // Inject checkPreimage(txPreimage) at the start
            let preimage_ref = method_ctx.emit(ANFValue::LoadParam {
                name: "txPreimage".to_string(),
            });
            let check_result = method_ctx.emit(ANFValue::CheckPreimage {
                preimage: preimage_ref,
                // Omit for the default so the ANF (and pinned binding blob) is
                // byte-identical; `sighash_flag` is None unless non-default.
                sighash_flag: method_ctx.sighash_flag,
            });
            method_ctx.emit(ANFValue::Assert {
                value: check_result,
                is_auto_injected_state_check: false,
            });

            // GAP-302 / #123: pin the sighash type to the declared mode. The
            // auto-injected covenant verifies a real tx preimage, but without
            // this check the spend could use a DIFFERENT sighash flag than
            // declared that zeroes out preimage fields the contract (or its
            // continuation) relies on (hashOutputs / hashPrevouts /
            // hashSequence). The value defaults to 0x41 (ALL|FORKID) so existing
            // contracts emit byte-identical ANF.
            let sig_hash_preimage_ref = method_ctx.emit(ANFValue::LoadParam {
                name: "txPreimage".to_string(),
            });
            let sig_hash_type_ref = method_ctx.emit(ANFValue::Call {
                func: "extractSigHashType".to_string(),
                args: vec![sig_hash_preimage_ref],
            });
            let expected_sig_hash_ref = method_ctx.emit(ANFValue::LoadConst {
                value: bigint_to_json(&BigInt::from(sighash_mode)),
            });
            let sig_hash_ok_ref = method_ctx.emit(ANFValue::BinOp {
                op: "===".to_string(),
                left: sig_hash_type_ref,
                right: expected_sig_hash_ref,
                result_type: None,
            });
            method_ctx.emit(ANFValue::Assert {
                value: sig_hash_ok_ref,
                is_auto_injected_state_check: false,
            });

            // Deserialize mutable state from the preimage's scriptCode.
            // On subsequent spends, the state is embedded in the script (after OP_RETURN),
            // so we extract it from the scriptCode field rather than using hardcoded initial values.
            let has_state_prop = contract.properties.iter().any(|p| !p.readonly);
            if has_state_prop {
                let preimage_ref3 = method_ctx.emit(ANFValue::LoadParam {
                    name: "txPreimage".to_string(),
                });
                method_ctx.emit(ANFValue::DeserializeState {
                    preimage: preimage_ref3,
                });
            }

            // Issue #109: preserve @embedAlways fields at the first
            // user-statement position (after the checkPreimage/deserialize
            // preamble), mirroring where a `const _bind = this.field;` idiom
            // would sit.
            if !embed_injected && !embed_fields.is_empty() {
                emit_embed_always_preservation(&mut method_ctx, &embed_fields);
                embed_injected = true;
            }

            // Lower the developer's method body
            lower_statements(&method.body, &mut method_ctx);

            // Determine state continuation type.
            //
            // === Continuation-hash construction ===
            //
            // The auto-injected continuation assertion verifies that the spending
            // transaction's hashOutputs field matches a compiler-constructed hash
            // over the outputs this method declares. Outputs are concatenated in
            // the following order before hashing with hash256:
            //
            //   1. state outputs   (from this.addOutput / this.addRawOutput,
            //                       tracked via add_output_refs)
            //   2. data outputs    (from this.addDataOutput, tracked via
            //                       add_data_output_refs)
            //   3. change output   (P2PKH to _changePKH, value = _changeAmount)
            //
            // For the "single-output" fast path (no addOutput used, but state
            // is mutated), the state output is computed on the fly from
            // (preimage, stateScript, _newAmount). Data outputs may still be
            // declared in this mode and are inserted BETWEEN the single state
            // output and the change output.
            let add_output_refs = method_ctx.add_output_refs.clone();
            let add_data_output_refs = method_ctx.add_data_output_refs.clone();
            // Gate the continuation assertion on the same shape used
            // for param injection. Both must agree or the deployed
            // locking script will not match the auto-injected
            // parameter list.
            if needs_change_output {
                // Build the P2PKH change output for hashOutputs verification.
                //
                // Issue #116: the SDK's build_call_transaction OMITS the change
                // output when `change <= 0` (an exact-cover call) and passes
                // `_changeAmount = 0`. Gate the change segment on
                // `_changeAmount != 0` at runtime so the hashed output set
                // matches the SDK at the exact-zero boundary — the segment is
                // the P2PKH change output when non-zero, and empty bytes (cat
                // with empty is a no-op) when zero, reproducing the omission.
                // For any change > 0 the hashed bytes are unchanged; only the
                // emitted script gains the guard.
                let change_pkh_ref = method_ctx.emit(ANFValue::LoadParam {
                    name: "_changePKH".to_string(),
                });
                let change_amount_ref = method_ctx.emit(ANFValue::LoadParam {
                    name: "_changeAmount".to_string(),
                });
                let zero_ref = method_ctx.emit(ANFValue::LoadConst {
                    value: bigint_to_json(&BigInt::from(0)),
                });
                let change_nonzero_ref = method_ctx.emit(ANFValue::BinOp {
                    op: "!==".to_string(),
                    left: change_amount_ref.clone(),
                    right: zero_ref,
                    result_type: None,
                });
                let mut change_then_ctx = method_ctx.sub_context();
                change_then_ctx.emit(ANFValue::Call {
                    func: "buildChangeOutput".to_string(),
                    args: vec![change_pkh_ref, change_amount_ref],
                });
                method_ctx.sync_counter(&change_then_ctx);
                let mut change_else_ctx = method_ctx.sub_context();
                change_else_ctx.emit(ANFValue::LoadConst {
                    value: serde_json::Value::String(String::new()),
                });
                method_ctx.sync_counter(&change_else_ctx);
                let change_output_ref = method_ctx.emit(ANFValue::If {
                    cond: change_nonzero_ref,
                    then: change_then_ctx.bindings,
                    else_branch: change_else_ctx.bindings,
                    results: Vec::new(),
                });

                if !add_output_refs.is_empty() {
                    // Multi-output continuation: concat all state outputs, then
                    // all data outputs, then change output, then hash.
                    let mut accumulated = add_output_refs[0].clone();
                    for i in 1..add_output_refs.len() {
                        accumulated = method_ctx.emit(ANFValue::Call {
                            func: "cat".to_string(),
                            args: vec![accumulated, add_output_refs[i].clone()],
                        });
                    }
                    for data_ref in &add_data_output_refs {
                        accumulated = method_ctx.emit(ANFValue::Call {
                            func: "cat".to_string(),
                            args: vec![accumulated, data_ref.clone()],
                        });
                    }
                    accumulated = method_ctx.emit(ANFValue::Call {
                        func: "cat".to_string(),
                        args: vec![accumulated, change_output_ref],
                    });
                    let hash_ref = method_ctx.emit(ANFValue::Call {
                        func: "hash256".to_string(),
                        args: vec![accumulated],
                    });
                    let preimage_ref2 = method_ctx.emit(ANFValue::LoadParam {
                        name: "txPreimage".to_string(),
                    });
                    let output_hash_ref = method_ctx.emit(ANFValue::Call {
                        func: "extractOutputHash".to_string(),
                        args: vec![preimage_ref2],
                    });
                    let eq_ref = method_ctx.emit(ANFValue::BinOp {
                        op: "===".to_string(),
                        left: hash_ref,
                        right: output_hash_ref,
                        result_type: Some("bytes".to_string()),
                    });
                    method_ctx.emit(ANFValue::Assert { value: eq_ref, is_auto_injected_state_check: true });
                } else {
                    // Single-output continuation: build raw state output bytes,
                    // then splice in any declared data outputs, then concat
                    // with change, then hash.
                    let state_script_ref = method_ctx.emit(ANFValue::GetStateScript {});
                    let preimage_ref2 = method_ctx.emit(ANFValue::LoadParam {
                        name: "txPreimage".to_string(),
                    });
                    let new_amount_ref = method_ctx.emit(ANFValue::LoadParam {
                        name: "_newAmount".to_string(),
                    });
                    let contract_output_ref = method_ctx.emit(ANFValue::Call {
                        func: "computeStateOutput".to_string(),
                        args: vec![preimage_ref2.clone(), state_script_ref, new_amount_ref],
                    });
                    let mut accumulated = contract_output_ref;
                    for data_ref in &add_data_output_refs {
                        accumulated = method_ctx.emit(ANFValue::Call {
                            func: "cat".to_string(),
                            args: vec![accumulated, data_ref.clone()],
                        });
                    }
                    let all_outputs = method_ctx.emit(ANFValue::Call {
                        func: "cat".to_string(),
                        args: vec![accumulated, change_output_ref],
                    });
                    let hash_ref = method_ctx.emit(ANFValue::Call {
                        func: "hash256".to_string(),
                        args: vec![all_outputs],
                    });
                    let preimage_ref4 = method_ctx.emit(ANFValue::LoadParam {
                        name: "txPreimage".to_string(),
                    });
                    let output_hash_ref = method_ctx.emit(ANFValue::Call {
                        func: "extractOutputHash".to_string(),
                        args: vec![preimage_ref4],
                    });
                    let eq_ref = method_ctx.emit(ANFValue::BinOp {
                        op: "===".to_string(),
                        left: hash_ref,
                        right: output_hash_ref,
                        result_type: Some("bytes".to_string()),
                    });
                    method_ctx.emit(ANFValue::Assert { value: eq_ref, is_auto_injected_state_check: true });
                }
            }

            // Build augmented params list for ABI
            let mut augmented_params = lower_params(&method.params);
            if needs_change_output {
                augmented_params.push(ANFParam {
                    name: "_changePKH".to_string(),
                    param_type: "Ripemd160".to_string(),
                });
                augmented_params.push(ANFParam {
                    name: "_changeAmount".to_string(),
                    param_type: "bigint".to_string(),
                });
            }
            if needs_new_amount {
                augmented_params.push(ANFParam {
                    name: "_newAmount".to_string(),
                    param_type: "bigint".to_string(),
                });
            }
            augmented_params.push(ANFParam {
                name: "txPreimage".to_string(),
                param_type: "SigHashPreimage".to_string(),
            });

            // Intent-covenant intrinsic auto-injected witness params:
            // extractPrevOutputScript adds `_prevOutScript_<inputIndex>`
            // (one per distinct literal index referenced in the method);
            // requireOutputP2PKH adds a single `_serialisedOutputs`. Order
            // follows insertion order via method_scope.auto_injected_params.
            // Appended AFTER txPreimage so unlocking scripts push them
            // adjacent to the preimage (matches existing _changePKH /
            // _changeAmount / _newAmount convention of trailing the user
            // args before the preimage anchor).
            for p in method_ctx.method_scope.borrow().auto_injected_params.iter() {
                augmented_params.push(p.clone());
            }

            result.push(ANFMethod {
                name: method.name.clone(),
                params: augmented_params,
                body: method_ctx.bindings,
                is_public: true,
                sighash_type: method.sighash_type,
            });
        } else {
            // Issue #109: stateless public methods (and stateless contracts'
            // spending entry points) are lowered here — inject @embedAlways
            // preservation into the first PUBLIC one before its body.
            if !embed_injected
                && !embed_fields.is_empty()
                && method.visibility == Visibility::Public
            {
                emit_embed_always_preservation(&mut method_ctx, &embed_fields);
                embed_injected = true;
            }
            lower_statements(&method.body, &mut method_ctx);
            // Private methods can also call the intent intrinsics; surface
            // their auto-injected witness params on the private method's
            // own ABI. (Private methods are typically inlined into public
            // bodies via inline_private_method_call — that path reuses the
            // public's method_scope, so the auto-injection registers at
            // the public method's ABI augmentation step above.)
            let mut augmented = lower_params(&method.params);
            for p in method_ctx.method_scope.borrow().auto_injected_params.iter() {
                augmented.push(p.clone());
            }
            result.push(ANFMethod {
                name: method.name.clone(),
                params: augmented,
                body: method_ctx.bindings,
                is_public: method.visibility == Visibility::Public,
                sighash_type: method.sighash_type,
            });
        }
    }

    result
}

/// Issue #109: emit the DCE-surviving preservation pair for each
/// `@embedAlways` readonly field into the given (public) method context.
///
/// Reproduces exactly what a hand-written `const _bind = this.field;` lowers
/// to: a `load_prop` followed by a `load_const("@ref:<t>")` alias. The alias
/// marks the `load_prop` as referenced (see `collect_refs_from_value` in
/// `frontend/dce.rs`), so dead-binding DCE keeps it; stack lowering then emits
/// the field's constructor-slot placeholder and NIPs the unused value off the
/// stack at method end, so the field's bytes remain in the deployed script.
fn emit_embed_always_preservation(ctx: &mut LoweringContext, fields: &[&PropertyNode]) {
    for field in fields {
        let load_ref = ctx.emit(ANFValue::LoadProp {
            name: field.name.clone(),
        });
        ctx.emit_named(
            &format!("__embedAlways_{}", field.name),
            ANFValue::LoadConst {
                value: serde_json::Value::String(format!("@ref:{}", load_ref)),
            },
        );
    }
}

fn lower_params(params: &[ParamNode]) -> Vec<ANFParam> {
    params
        .iter()
        .map(|p| ANFParam {
            name: p.name.clone(),
            param_type: type_node_to_string(&p.param_type),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Lowering context
//
// Mirrors the TypeScript LoweringContext class exactly:
// - No parameter pre-loading (params are loaded lazily on first reference)
// - addParam is never called (matching TS where addParam exists but is unused)
// - Local variables are tracked via localNames set
// - Properties are checked against the contract
// ---------------------------------------------------------------------------

/// Per-method bookkeeping shared by the parent lowering context and any
/// sub-contexts spawned for nested blocks (if/else, ternary). The ABI
/// augmentation pass — after lowering a method body — reads
/// `auto_injected_params` to append witness params to the final ABI list.
///
/// Mirrors Go's `methodScopeT` (compilers/go/frontend/anf_lower.go). Used by
/// the intent-covenant intrinsics extractPrevOutputScript and
/// requireOutputP2PKH; currentBlockHeight is a pure desugar with no
/// auto-injected param.
#[derive(Default)]
struct MethodScope {
    /// Append-only, insertion-order list of auto-injected witness params.
    auto_injected_params: Vec<ANFParam>,
    /// Dedup set for `auto_injected_params`.
    auto_injected_set: HashSet<String>,
    /// requireOutputP2PKH emits its `hash256(serialisedOutputs) ==
    /// extractOutputHash(txPreimage)` check at most once per method body.
    did_emit_hash_outputs_check: bool,
}

impl MethodScope {
    /// Record a witness param needed by an intrinsic call. Idempotent —
    /// the second call with the same name is a no-op.
    fn record_auto_injected_param(&mut self, name: &str, ty: &str) {
        if self.auto_injected_set.contains(name) {
            return;
        }
        self.auto_injected_set.insert(name.to_string());
        self.auto_injected_params.push(ANFParam {
            name: name.to_string(),
            param_type: ty.to_string(),
        });
    }
}

struct LoweringContext<'a> {
    bindings: Vec<ANFBinding>,
    counter: usize,
    contract: &'a ContractNode,
    param_names: HashSet<String>,
    local_names: HashSet<String>,
    /// Refs for state outputs (this.addOutput / this.addRawOutput). These
    /// appear first in the continuation-hash composition.
    add_output_refs: Vec<String>,
    /// Refs for data outputs (this.addDataOutput). These appear after state
    /// outputs and before the change output in the continuation-hash
    /// composition. Wire shape is identical to add_raw_output.
    add_data_output_refs: Vec<String>,
    /// Maps local variable names to their current ANF binding name.
    /// Updated after if-statements that reassign locals in both branches.
    local_aliases: HashMap<String, String>,
    /// Tracks local variables known to be byte-typed.
    local_byte_vars: HashSet<String>,
    /// Maps the CURRENT method's (or constructor's) parameter names to their
    /// declared type strings. Populated once per method/constructor before
    /// lowering its body and shared into if/else sub-contexts. Method-scoped
    /// so a local named `x` in one method cannot falsely match a same-named
    /// parameter of a DIFFERENT method during byte-type analysis (issue #34).
    param_types: HashMap<String, String>,
    /// Current source location for debug source maps. Set from each AST statement's
    /// source_location and propagated to emitted ANF bindings.
    current_source_loc: Option<SourceLocation>,
    /// Param substitution stack used when inlining a private method's
    /// body directly into this context. When the inlined body
    /// references that param, the lowered identifier resolves to the
    /// aliased ref instead of emitting load_param. Stacked so nested
    /// inlines compose correctly.
    param_alias_stack: HashMap<String, Vec<String>>,
    /// Side-effect summary shared with auto-injection decisions. Used
    /// at lowering time to decide whether a private call should be
    /// inlined (so that helper's add_output / add_data_output ANF
    /// nodes register on the caller's continuation hash) or remain a
    /// method_call for stack lowering to inline later.
    side_effects: Option<SideEffectSummary>,
    /// Per-method state shared with all sub-contexts. Tracks auto-injected
    /// witness parameters needed by intent-covenant intrinsics
    /// (extractPrevOutputScript, requireOutputP2PKH) regardless of whether
    /// the intrinsic is called from the method's top-level body or from
    /// inside a nested block (if/else, ternary). Shared via Rc<RefCell<>>
    /// so sub-contexts mutate the same scope the parent reads from.
    method_scope: Rc<RefCell<MethodScope>>,
    /// Issue #123: the declared non-default `@sighash` flag for the method
    /// being lowered, so a MANUAL `checkPreimage(pre)` call (stateless /
    /// explicit) AND the auto-injected covenant bind under the same mode as the
    /// method's declared sighash. `None` = default ALL|FORKID, keeping the
    /// pinned binding blob unchanged.
    sighash_flag: Option<i64>,
    /// True in every context produced by `sub_context()` — inside an if arm, a
    /// loop body, or an inlined helper's block — and false only in the context a
    /// method's own body is lowered into.
    nested: bool,
}

impl<'a> LoweringContext<'a> {
    fn new(contract: &'a ContractNode) -> Self {
        Self::with_effects(contract, None)
    }

    fn with_effects(contract: &'a ContractNode, side_effects: Option<SideEffectSummary>) -> Self {
        LoweringContext {
            bindings: Vec::new(),
            counter: 0,
            contract,
            param_names: HashSet::new(),
            local_names: HashSet::new(),
            add_output_refs: Vec::new(),
            add_data_output_refs: Vec::new(),
            local_aliases: HashMap::new(),
            local_byte_vars: HashSet::new(),
            param_types: HashMap::new(),
            current_source_loc: None,
            param_alias_stack: HashMap::new(),
            side_effects,
            method_scope: Rc::new(RefCell::new(MethodScope::default())),
            sighash_flag: None,
            nested: false,
        }
    }

    /// Push an alias frame for the named param. Subsequent identifier
    /// lookups for `name` resolve to `alias_ref` until the matching
    /// pop. Stacked so nested inlines compose: pop returns the
    /// previous frame.
    fn push_param_alias(&mut self, name: &str, alias_ref: &str) {
        self.param_alias_stack
            .entry(name.to_string())
            .or_default()
            .push(alias_ref.to_string());
    }

    fn pop_param_alias(&mut self, name: &str) {
        let key = name.to_string();
        if let Some(stack) = self.param_alias_stack.get_mut(&key) {
            stack.pop();
            if stack.is_empty() {
                self.param_alias_stack.remove(&key);
            }
        }
    }

    fn get_param_alias(&self, name: &str) -> Option<&String> {
        self.param_alias_stack
            .get(name)
            .and_then(|s| s.last())
    }

    /// Returns true if a call to `name` should be ANF-inlined rather
    /// than emitted as a method_call. True iff `name` is a private
    /// method that (transitively) emits state outputs (addOutput /
    /// addRawOutput) or data outputs (addDataOutput). Those refs MUST
    /// appear in the caller's binding stream so they participate in
    /// the continuation hash.
    ///
    /// Mutation-only private helpers (no output intrinsics) are
    /// intentionally NOT inlined — state mutation flows through state
    /// continuity (the continuation hash reads state via
    /// `get_state_script` after all mutations apply). Keeping the
    /// existing `method_call` + stack-lowering inlining path for
    /// those preserves byte-equality with the pre-fix corpus.
    fn should_inline_private(&self, name: &str) -> bool {
        let summary = match self.side_effects.as_ref() {
            Some(s) => s,
            None => return false,
        };
        if !self.is_private_method(name) {
            return false;
        }
        match summary.get(name) {
            Some(eff) => eff.has_state_output || eff.has_data_output,
            None => false,
        }
    }

    /// Look up a private method by name.
    fn get_private_method(&self, name: &str) -> Option<&MethodNode> {
        self.contract.methods.iter().find(|m| {
            m.name == name && !matches!(m.visibility, Visibility::Public)
        })
    }

    /// Generate a fresh temporary name.
    fn fresh_temp(&mut self) -> String {
        let name = format!("t{}", self.counter);
        self.counter += 1;
        name
    }

    /// Emit a binding and return the bound name.
    fn emit(&mut self, value: ANFValue) -> String {
        let name = self.fresh_temp();
        self.bindings.push(ANFBinding {
            name: name.clone(),
            value,
            source_loc: self.current_source_loc.clone(),
        });
        name
    }

    /// Emit a binding with a specific name (for named variables).
    fn emit_named(&mut self, name: &str, value: ANFValue) {
        self.bindings.push(ANFBinding {
            name: name.to_string(),
            value,
            source_loc: self.current_source_loc.clone(),
        });
    }

    /// Record a parameter name so we know to use load_param for it.
    fn add_param(&mut self, name: &str) {
        self.param_names.insert(name.to_string());
    }

    /// Register the declared type of a parameter belonging to the CURRENT
    /// method/constructor scope. Read back by `get_param_type` for byte-type
    /// analysis. Auto-injected continuation params register here too.
    fn register_param_type(&mut self, name: &str, ty: &str) {
        self.param_types.insert(name.to_string(), ty.to_string());
    }

    fn is_param(&self, name: &str) -> bool {
        self.param_names.contains(name)
    }

    /// Record a local variable name.
    fn add_local(&mut self, name: &str) {
        self.local_names.insert(name.to_string());
    }

    fn is_local(&self, name: &str) -> bool {
        self.local_names.contains(name)
    }

    /// Set the current ANF binding for a local variable (after if-statement reassignment).
    fn set_local_alias(&mut self, local_name: &str, binding_name: &str) {
        self.local_aliases
            .insert(local_name.to_string(), binding_name.to_string());
    }

    /// Get the current ANF binding for a local variable, or None if not aliased.
    fn get_local_alias(&self, name: &str) -> Option<&String> {
        self.local_aliases.get(name)
    }

    fn is_property(&self, name: &str) -> bool {
        self.contract.properties.iter().any(|p| p.name == name)
    }

    /// Report whether `name` is a private (non-public) method on the contract.
    /// Used to route bare-identifier calls (e.g. Move's `require_owner(sig)`
    /// after `contract` stripping) through the method_call inlining path.
    fn is_private_method(&self, name: &str) -> bool {
        self.contract.methods.iter().any(|m| {
            m.name == name
                && m.name != "constructor"
                && !matches!(m.visibility, Visibility::Public)
        })
    }

    /// Create a sub-context for nested blocks (if/else, loops).
    /// The counter continues from the parent. Local names, param names, and aliases are shared.
    fn sub_context(&self) -> LoweringContext<'a> {
        let mut sub = LoweringContext::with_effects(self.contract, self.side_effects.clone());
        sub.counter = self.counter;
        sub.param_names = self.param_names.clone();
        sub.local_names = self.local_names.clone();
        sub.local_aliases = self.local_aliases.clone();
        sub.local_byte_vars = self.local_byte_vars.clone();
        // Share the current method's parameter types so byte-type analysis
        // inside nested blocks resolves params against the SAME method scope
        // the parent reads from (issue #34).
        sub.param_types = self.param_types.clone();
        sub.current_source_loc = self.current_source_loc.clone();
        sub.param_alias_stack = self.param_alias_stack.clone();
        // Share the per-method scope so intrinsic auto-injection from
        // inside a nested block (if/else, ternary) registers on the
        // parent method's ABI augmentation pass.
        sub.method_scope = Rc::clone(&self.method_scope);
        // Issue #123: a manual checkPreimage inside a nested block must bind
        // under the method's declared @sighash mode.
        sub.sighash_flag = self.sighash_flag;
        // `lift_branch_update_props` walks method.body and does NOT recurse, so
        // an `if` its recogniser accepts is only actually REWRITTEN at method
        // top level. `lower_if_statement` needs the same distinction before it
        // defers to that pass.
        sub.nested = true;
        // Note: add_output_refs is NOT propagated to sub-contexts
        // because addOutput calls in sub-blocks should flow up to
        // the parent context via explicit tracking.
        sub
    }

    /// Sync the counter back from a sub-context.
    fn sync_counter(&mut self, sub: &LoweringContext) {
        if sub.counter > self.counter {
            self.counter = sub.counter;
        }
    }
}

// ---------------------------------------------------------------------------
// Statement lowering
// ---------------------------------------------------------------------------

fn lower_statements(stmts: &[Statement], ctx: &mut LoweringContext) {
    lower_statements_with_reads(stmts, ctx, &HashSet::new());
}

/// Lower a statement block, threading down the set of identifiers the enclosing
/// blocks still read after this block ends. Only the block-forming statements
/// (if / for) consume it; see `reads_after_statement`.
fn lower_statements_with_reads(
    stmts: &[Statement],
    ctx: &mut LoweringContext,
    reads_after_block: &HashSet<String>,
) {
    for i in 0..stmts.len() {
        let stmt = &stmts[i];
        // When an if-statement has no else, the then-block ends with return,
        // and there are remaining statements: nest the remaining statements
        // into the else branch. This handles early-return patterns in private methods.
        if let Statement::IfStatement {
            condition,
            then_branch,
            else_branch: None,
            source_location,
        } = stmt
        {
            if i + 1 < stmts.len() && branch_ends_with_return(then_branch) {
                let remaining = stmts[i + 1..].to_vec();
                let modified_if = Statement::IfStatement {
                    condition: condition.clone(),
                    then_branch: then_branch.clone(),
                    else_branch: Some(remaining),
                    source_location: source_location.clone(),
                };
                lower_statement_with_reads(&modified_if, ctx, reads_after_block);
                return;
            }
        }
        // Only the block-forming statements need to know what the code after
        // them still reads; computing it for every statement would be quadratic
        // for no benefit.
        match stmt {
            Statement::IfStatement { .. } | Statement::ForStatement { .. } => {
                let reads_after = reads_after_statement(stmts, i, reads_after_block);
                lower_statement_with_reads(stmt, ctx, &reads_after);
            }
            _ => lower_statement(stmt, ctx),
        }
    }
}

/// The identifiers still readable once statement `index` of this block has run:
/// everything the following statements in this block read, plus whatever the
/// enclosing blocks read after this block.
///
/// Used by `lower_if_statement` to tell a branch-merged local that is dead after
/// the `if` (safe) from one that is still live (not representable alongside a
/// branch output — see `branch_output_rejection_reason`).
fn reads_after_statement(
    stmts: &[Statement],
    index: usize,
    reads_after_block: &HashSet<String>,
) -> HashSet<String> {
    let mut reads = reads_after_block.clone();
    for stmt in &stmts[index + 1..] {
        collect_statement_reads(stmt, &mut reads);
    }
    reads
}

/// Collect every identifier a statement READS. The `x` in `x = expr` is a write,
/// not a read, so a plain identifier assignment target is skipped; every other
/// target form can still read locals.
fn collect_statement_reads(stmt: &Statement, out: &mut HashSet<String>) {
    match stmt {
        Statement::VariableDecl { init, .. } => collect_expression_reads(init, out),
        Statement::Assignment { target, value, .. } => {
            if !matches!(target, Expression::Identifier { .. }) {
                collect_expression_reads(target, out);
            }
            collect_expression_reads(value, out);
        }
        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            collect_expression_reads(condition, out);
            for s in then_branch {
                collect_statement_reads(s, out);
            }
            if let Some(else_stmts) = else_branch {
                for s in else_stmts {
                    collect_statement_reads(s, out);
                }
            }
        }
        Statement::ForStatement {
            init,
            condition,
            update,
            body,
            ..
        } => {
            collect_statement_reads(init, out);
            collect_expression_reads(condition, out);
            collect_statement_reads(update, out);
            for s in body {
                collect_statement_reads(s, out);
            }
        }
        Statement::ReturnStatement { value, .. } => {
            if let Some(v) = value {
                collect_expression_reads(v, out);
            }
        }
        Statement::ExpressionStatement { expression, .. } => {
            collect_expression_reads(expression, out)
        }
    }
}

/// Collect every identifier an expression reads.
fn collect_expression_reads(expr: &Expression, out: &mut HashSet<String>) {
    match expr {
        Expression::Identifier { name } => {
            out.insert(name.clone());
        }
        Expression::BinaryExpr { left, right, .. } => {
            collect_expression_reads(left, out);
            collect_expression_reads(right, out);
        }
        Expression::UnaryExpr { operand, .. } => collect_expression_reads(operand, out),
        Expression::CallExpr { callee, args, .. } => {
            collect_expression_reads(callee, out);
            for a in args {
                collect_expression_reads(a, out);
            }
        }
        Expression::MemberExpr { object, .. } => collect_expression_reads(object, out),
        Expression::TernaryExpr {
            condition,
            consequent,
            alternate,
        } => {
            collect_expression_reads(condition, out);
            collect_expression_reads(consequent, out);
            collect_expression_reads(alternate, out);
        }
        Expression::IndexAccess { object, index } => {
            collect_expression_reads(object, out);
            collect_expression_reads(index, out);
        }
        Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => {
            collect_expression_reads(operand, out)
        }
        Expression::ArrayLiteral { elements } => {
            for e in elements {
                collect_expression_reads(e, out);
            }
        }
        // Literals and `this.x` property access read no locals.
        _ => {}
    }
}

/// Check if a branch (slice of statements) ends with a return statement,
/// or with an if-statement where both branches end with a return.
fn branch_ends_with_return(stmts: &[Statement]) -> bool {
    if stmts.is_empty() {
        return false;
    }
    let last = &stmts[stmts.len() - 1];
    match last {
        Statement::ReturnStatement { .. } => true,
        Statement::IfStatement {
            then_branch,
            else_branch: Some(else_branch),
            ..
        } => branch_ends_with_return(then_branch) && branch_ends_with_return(else_branch),
        _ => false,
    }
}

/// Extract the source location from any Statement variant.
fn statement_source_location(stmt: &Statement) -> &super::ast::SourceLocation {
    match stmt {
        Statement::VariableDecl { source_location, .. }
        | Statement::Assignment { source_location, .. }
        | Statement::IfStatement { source_location, .. }
        | Statement::ForStatement { source_location, .. }
        | Statement::ReturnStatement { source_location, .. }
        | Statement::ExpressionStatement { source_location, .. } => source_location,
    }
}

fn lower_statement(stmt: &Statement, ctx: &mut LoweringContext) {
    lower_statement_with_reads(stmt, ctx, &HashSet::new());
}

fn lower_statement_with_reads(
    stmt: &Statement,
    ctx: &mut LoweringContext,
    reads_after: &HashSet<String>,
) {
    // Propagate source location to emitted ANF bindings
    let ast_loc = statement_source_location(stmt);
    ctx.current_source_loc = Some(SourceLocation {
        file: ast_loc.file.clone(),
        line: ast_loc.line,
        column: ast_loc.column,
    });

    match stmt {
        Statement::VariableDecl {
            name, init, ..
        } => {
            lower_variable_decl(name, init, ctx);
        }
        Statement::Assignment { target, value, .. } => {
            lower_assignment(target, value, ctx);
        }
        Statement::IfStatement {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            lower_if_statement(condition, then_branch, else_branch.as_deref(), ctx, reads_after);
        }
        Statement::ForStatement {
            init,
            condition,
            update,
            body,
            ..
        } => {
            lower_for_statement(init, condition, update, body, ctx, reads_after);
        }
        Statement::ExpressionStatement { expression, .. } => {
            lower_expr_to_ref(expression, ctx);
        }
        Statement::ReturnStatement { value, .. } => {
            if let Some(v) = value {
                let ref_name = lower_expr_to_ref(v, ctx);
                // If the returned ref is not the name of the last emitted binding,
                // emit an explicit @ref: alias so the return value is the last
                // (top-of-stack) binding. This matters when a local variable is
                // returned after control flow (e.g., `let count = 0n; if (...) {
                // count += 1n; } return count;`). Without this, the last binding
                // is the if, not `count`, so inline_method_call in stack lowering
                // can't find the return value.
                if let Some(last) = ctx.bindings.last() {
                    if last.name != ref_name {
                        ctx.emit(ANFValue::LoadConst {
                            value: serde_json::Value::String(format!("@ref:{}", ref_name)),
                        });
                    }
                }
            }
        }
    }
}

/// Lower a variable declaration. Matches the TS reference:
/// Lower the init expression, register the variable as local, then emit
/// a named binding that aliases the variable to the computed value via @ref.
fn lower_variable_decl(name: &str, init: &Expression, ctx: &mut LoweringContext) {
    let value_ref = lower_expr_to_ref(init, ctx);
    ctx.add_local(name);
    if is_byte_typed_expr(init, ctx) {
        ctx.local_byte_vars.insert(name.to_string());
    }
    ctx.emit_named(
        name,
        ANFValue::LoadConst {
            value: serde_json::Value::String(format!("@ref:{}", value_ref)),
        },
    );
}

/// Lower an assignment. Matches the TS reference:
/// For this.x = expr -> emit update_prop
/// For local = expr -> emit named binding with @ref alias
fn lower_assignment(target: &Expression, value: &Expression, ctx: &mut LoweringContext) {
    let value_ref = lower_expr_to_ref(value, ctx);

    // this.x = expr -> update_prop
    if let Expression::PropertyAccess { property } = target {
        ctx.emit(ANFValue::UpdateProp {
            name: property.clone(),
            value: value_ref,
        });
        return;
    }

    // local = expr -> re-bind (emit a new named binding with @ref)
    if let Expression::Identifier { name } = target {
        ctx.emit_named(
            name,
            ANFValue::LoadConst {
                value: serde_json::Value::String(format!("@ref:{}", value_ref)),
            },
        );
        return;
    }

    // For other targets, lower them
    lower_expr_to_ref(target, ctx);
}

fn lower_if_statement(
    condition: &Expression,
    then_branch: &[Statement],
    else_branch: Option<&[Statement]>,
    ctx: &mut LoweringContext,
    reads_after: &HashSet<String>,
) {
    let cond_ref = lower_expr_to_ref(condition, ctx);

    // Lower then-block into sub-context
    let mut then_ctx = ctx.sub_context();
    lower_statements_with_reads(then_branch, &mut then_ctx, reads_after);
    ctx.sync_counter(&then_ctx);

    // Lower else-block into sub-context
    let mut else_ctx = ctx.sub_context();
    if let Some(else_stmts) = else_branch {
        lower_statements_with_reads(else_stmts, &mut else_ctx, reads_after);
    }
    ctx.sync_counter(&else_ctx);

    // 2026-04-30 audit finding F2: when a branch contains output
    // intrinsics, append a cat-chain inside each branch so the
    // branch's terminal value is the concat of its output bytes
    // (state then data, in declaration order). This balances the
    // runtime stack effect across branches and lets the parent's
    // continuation hash see one ref per if representing the chosen
    // branch's full output set.
    let branch_has_state_output =
        !then_ctx.add_output_refs.is_empty() || !else_ctx.add_output_refs.is_empty();
    let branch_has_outputs = branch_has_state_output
        || !then_ctx.add_data_output_refs.is_empty()
        || !else_ctx.add_data_output_refs.is_empty();

    let mut then_output_bytes = String::new();
    let mut else_output_bytes = String::new();
    if branch_has_outputs {
        then_output_bytes = append_branch_output_concat(&mut then_ctx);
        else_output_bytes = append_branch_output_concat(&mut else_ctx);
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
    // Fix: give both arms the SAME result set in the SAME order by appending
    // an explicit rebind of every merged local to each arm.
    let merged_locals = collect_branch_merged_locals(&then_ctx, &else_ctx, ctx);

    if branch_has_outputs {
        if let Some(reason) = branch_output_rejection_reason(
            &then_ctx,
            &else_ctx,
            &then_output_bytes,
            &else_output_bytes,
            &merged_locals,
            reads_after,
        ) {
            panic!(
                "Cannot compile conditional that both declares outputs and {}. \
                 Move the addOutput/addRawOutput/addDataOutput call after the \
                 if-statement.",
                reason
            );
        }
    }

    // The `if`'s multi-result contract. Locals first, in the canonical merge
    // order both arms agree on, then the properties either arm writes, in
    // contract declaration order — so all seven tiers derive the same list from
    // the same source. `results[0]` is the deepest slot of the block.
    let mut arm_props: Vec<String> = Vec::new();
    collect_updated_props(&then_ctx.bindings, &mut arm_props);
    collect_updated_props(&else_ctx.bindings, &mut arm_props);
    let mut result_names = merged_locals.clone();
    for p in ctx.contract.properties.iter() {
        if arm_props.contains(&p.name) {
            result_names.push(p.name.clone());
        }
    }

    // The result list is keyed by NAME everywhere downstream, so a local that
    // shares a contract property's name appears TWICE and both entries take the
    // PROPERTY path — the local's value is silently replaced by the property's,
    // and the layout assertion cannot see it because both slots are legitimately
    // named the same. Refuse the exact collision only.
    if let Some(name) = merged_locals.iter().find(|n| arm_props.contains(n)) {
        panic!(
            "Local variable '{name}' shadows contract property 'this.{name}', and \
             the conditional assigns both. The branch's result slots are identified \
             by name, so the two cannot be told apart and the local's value would \
             be silently replaced by the property's. Rename the local."
        );
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
    // `lower_if` (phase 3 copies each missing slot's same-named parent value),
    // which already produces exactly these results by construction —
    // deliberately left intact. An arm that emits outputs is excluded: its
    // single value is the serialised output bytes, and
    // `branch_output_rejection_reason` above already refuses every combination
    // that would need a second result.
    //
    // EXCLUDED: an `if` that `lift_branch_update_props` will rewrite. That pass
    // (deep-review finding C20) turns a conditional-property-assignment chain
    // into one flat single-valued `if` per property plus a top-level
    // `update_prop`, so the surviving `if`s carry no property result and need
    // no declaration. Appending the normalisation block first would ALSO
    // silently disable that pass: its recogniser requires the arm's last
    // binding to be the `update_prop` with everything before it side-effect
    // free, and the block adds a second `update_prop` behind it. TicTacToe's
    // position dispatch is exactly that shape, and losing the lift there
    // produced an unspendable `move` script.
    //
    // The exclusion must be exactly "the lift WILL rewrite this `if`", which is
    // narrower than "the lift's recogniser accepts it" in TWO ways — both were
    // live defects producing an unspendable UTXO: the lift only rewrites chains
    // of TWO OR MORE branches (`collect_update_branches` returns a ONE-element
    // list for the assert-false-else guard), and it only walks `method.body`,
    // passing loop bodies and surviving arms through untouched, while
    // `declares_results` is evaluated at EVERY nesting depth.
    //
    // A chain's DEEPEST `if` is never at top level, so it now declares results
    // and carries a normalisation block — which is why `collect_update_branches`
    // strips a declared block before matching (`strip_declared_results`).
    let lifted = collect_update_branches(&cond_ref, &then_ctx.bindings, &else_ctx.bindings);
    let will_be_lifted = !ctx.nested && lifted.as_ref().is_some_and(|b| b.len() >= 2);
    let declares_results = !branch_has_outputs
        && !will_be_lifted
        && (merged_locals.len() >= 2
            || (!result_names.is_empty() && !else_ctx.bindings.is_empty()));

    if declares_results {
        append_branch_results(&mut then_ctx, &result_names, &arm_props);
        ctx.sync_counter(&then_ctx);
        append_branch_results(&mut else_ctx, &result_names, &arm_props);
        ctx.sync_counter(&else_ctx);
    }

    let then_bindings = then_ctx.bindings;
    let else_bindings = else_ctx.bindings;

    // If both branches end by reassigning the same single local variable,
    // alias that variable to the if-expression result so that subsequent
    // references resolve to the branch output, not the dead initial value.
    //
    // Skipped when the arms were normalised above: there the `if` DECLARES its
    // results, and each one keeps its OWN name through the reconcile in the
    // stack lowerer.
    let then_last = then_bindings.last();
    let else_last = else_bindings.last();
    let alias_local = match (then_last, else_last) {
        (Some(tl), Some(el))
            if !declares_results && tl.name == el.name && ctx.is_local(&tl.name) =>
        {
            Some(tl.name.clone())
        }
        _ => None,
    };

    let if_name = ctx.emit(ANFValue::If {
        cond: cond_ref,
        then: then_bindings,
        else_branch: else_bindings,
        results: if declares_results {
            result_names
        } else {
            Vec::new()
        },
    });

    if branch_has_outputs {
        // Register the if's value once with the parent's continuation
        // tracker. CRITICAL: pick the right tracker. If either branch
        // produces a STATE output (addOutput / addRawOutput), the
        // parent must take the multi-output continuation path, so we
        // register as a state output ref. If neither branch produces
        // a state output and at least one branch produces a data
        // output, we register as a DATA output ref so the parent
        // keeps its single-output `computeStateOutput` continuation
        // and the data-output bytes splice in BETWEEN the state
        // output and the change output. Without this, a branch with
        // only `addDataOutput` was incorrectly forced onto the
        // multi-output path, dropping the canonical state continuation.
        if branch_has_state_output {
            ctx.add_output_refs.push(if_name.clone());
        } else {
            ctx.add_data_output_refs.push(if_name.clone());
        }
    }

    if let Some(local_name) = alias_local {
        ctx.set_local_alias(&local_name, &if_name);
    }
}

/// The locals from the enclosing scope that either arm of an if-statement
/// reassigns, in a canonical order both arms can agree on: the then-arm's
/// reassignments in order of last rebind, then the else-only ones in the same
/// order.
///
/// Only names the PARENT already knows as locals count — `sub_context` copies
/// the local-name set by value, so a local declared inside a branch never
/// reaches the parent's set and is correctly excluded (it is not live after
/// the if).
fn collect_branch_merged_locals(
    then_ctx: &LoweringContext,
    else_ctx: &LoweringContext,
    ctx: &LoweringContext,
) -> Vec<String> {
    let last_rebind_order = |branch: &LoweringContext| -> Vec<String> {
        let mut order: Vec<(String, usize)> = Vec::new();
        for (i, b) in branch.bindings.iter().enumerate() {
            if !ctx.is_local(&b.name) {
                continue;
            }
            match order.iter_mut().find(|(n, _)| *n == b.name) {
                Some(entry) => entry.1 = i,
                None => order.push((b.name.clone(), i)),
            }
        }
        order.sort_by_key(|(_, i)| *i);
        order.into_iter().map(|(n, _)| n).collect()
    };
    let mut merged = last_rebind_order(then_ctx);
    for name in last_rebind_order(else_ctx) {
        if !merged.contains(&name) {
            merged.push(name);
        }
    }
    merged
}

/// Append the canonical result block to one arm of an if-statement: a copy of
/// every declared result, in the declared order, rebound under its own name.
/// This is what makes the `if` node's `results` contract true rather than
/// hoped-for.
///
/// Two passes on purpose. Pass 1 always COPIES: for a LOCAL, `@ref:<local>`
/// resolves to the arm's own new value if it rebound one, else to the
/// enclosing scope's value; for a PROPERTY, `load_prop` picks the arm's
/// updated slot when the arm wrote it and otherwise the enclosing value.
/// Either way stack lowering picks (never rolls) it, because a declared result
/// is outer-protected. Pass 2 always CONSUMES, because the temps are bound in
/// this arm and this is their last use. The arm's stack effect is therefore
/// exactly +N regardless of which of the N results it assigned.
///
/// Semantically a no-op for the off-chain ANF interpreters: every binding is
/// an ordinary read-then-write of a value the arm already holds.
fn append_branch_results(
    branch_ctx: &mut LoweringContext,
    result_names: &[String],
    props: &[String],
) {
    for (i, name) in result_names.iter().enumerate() {
        let temp = format!("{}{}", MERGED_LOCAL_TEMP_PREFIX, i);
        if props.contains(name) {
            branch_ctx.emit_named(&temp, ANFValue::LoadProp { name: name.clone() });
        } else {
            branch_ctx.emit_named(
                &temp,
                ANFValue::LoadConst {
                    value: serde_json::Value::String(format!("@ref:{}", name)),
                },
            );
        }
    }
    for (i, name) in result_names.iter().enumerate() {
        let temp = format!("{}{}", MERGED_LOCAL_TEMP_PREFIX, i);
        if props.contains(name) {
            branch_ctx.emit(ANFValue::UpdateProp {
                name: name.clone(),
                value: temp,
            });
        } else {
            branch_ctx.emit_named(
                name,
                ANFValue::LoadConst {
                    value: serde_json::Value::String(format!("@ref:{}", temp)),
                },
            );
        }
    }
}

/// Concatenate a branch's output refs (state then data, in declaration
/// order) into a single bytes-ref appended to the branch's bindings.
/// If the branch has no outputs, emits an empty `LoadConst` so the
/// branch still leaves one item on the stack — required to balance
/// the if's branch shapes when the OTHER branch has outputs.
/// 2026-04-30 audit finding F2 fix.
fn append_branch_output_concat(branch_ctx: &mut LoweringContext) -> String {
    let mut all_refs = branch_ctx.add_output_refs.clone();
    all_refs.extend(branch_ctx.add_data_output_refs.iter().cloned());
    if all_refs.is_empty() {
        return branch_ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::String(String::new()),
        });
    }
    if all_refs.len() == 1 {
        return all_refs[0].clone();
    }
    let mut accumulated = all_refs[0].clone();
    for next in &all_refs[1..] {
        accumulated = branch_ctx.emit(ANFValue::Call {
            func: "cat".to_string(),
            args: vec![accumulated, next.clone()],
        });
    }
    accumulated
}

/// Why an `if` whose arms declare outputs cannot be represented — or `None`
/// when it can. The result is the reason clause the diagnostic embeds.
///
/// An `if` expression carries exactly ONE value, and when an arm emits an output
/// that value is already spoken for: it is the output bytes the continuation
/// hash consumes (`append_branch_output_concat`). Anything ELSE the arm leaves
/// behind breaks one of two invariants that nothing downstream enforces:
///
///   - INV-A: the parent registers the if-expression's value as the branch's
///     contribution to the continuation hash, so "the branch's output bytes"
///     really means "whatever the arm's LAST binding is". A binding that lands
///     after the output — a rebound local, a property write — silently replaces
///     the serialized output with an unrelated value, and the residue drain then
///     physically drops the real output because it is no longer on top.
///   - INV-B: an arm that emits an output AND leaves any other slot the parent
///     can still name — a property write anywhere in the arm, or a rebound local
///     that is still read after the `if` — leaves 2+ results against the ONE
///     stackMap name the stack lowerer registers, desyncing the parent stack by
///     a slot from there on. The residue drain cannot save it: it filters BY
///     NAME and those names are all pre-`if` names.
///
/// Neither is visible off-chain, so both shipped as permanently unspendable
/// locking scripts. Refuse at compile time rather than emit one. See
/// packages/runar-testing/src/__tests__/branch-output-terminal-value-vm.test.ts
/// for the real-Script-VM proof of each shape.
///
/// The clauses are checked in a fixed order so all seven tiers report the same
/// reason for a source that trips more than one.
fn branch_output_rejection_reason(
    then_ctx: &LoweringContext,
    else_ctx: &LoweringContext,
    then_output_bytes: &str,
    else_output_bytes: &str,
    merged_locals: &[String],
    reads_after: &HashSet<String>,
) -> Option<String> {
    // 1. Two or more merged locals: normalising them would need a multi-result
    //    `if` node, and the arms' single value is already the output concat.
    if merged_locals.len() >= 2 {
        return Some(format!(
            "merges {} local variables ({})",
            merged_locals.len(),
            merged_locals.join(", ")
        ));
    }

    // 2. INV-A: the arm's terminal binding must BE its output bytes.
    let arms: [(&str, &LoweringContext, &str); 2] = [
        ("then", then_ctx, then_output_bytes),
        ("else", else_ctx, else_output_bytes),
    ];
    for (label, branch_ctx, output_bytes) in arms.iter() {
        match branch_ctx.bindings.last() {
            Some(last) if last.name == *output_bytes => {}
            _ => {
                return Some(format!(
                    "continues past its output in the {}-branch",
                    label
                ))
            }
        }
    }

    // 3. INV-B: a property write leaves a slot the parent can still name,
    //    wherever in the arm it sits.
    let mut written_props: Vec<String> = Vec::new();
    for (_, branch_ctx, _) in arms.iter() {
        collect_updated_props(&branch_ctx.bindings, &mut written_props);
    }
    if !written_props.is_empty() {
        return Some(format!(
            "assigns contract properties ({}) inside the branch",
            written_props.join(", ")
        ));
    }

    // 4. INV-B: a rebound local that survives the `if` is protected from being
    //    rolled away, so the arm ends one slot deeper than lowerIf accounts for.
    let live_merged: Vec<String> = merged_locals
        .iter()
        .filter(|name| reads_after.contains(*name))
        .cloned()
        .collect();
    if !live_merged.is_empty() {
        return Some(format!(
            "reassigns local variables read after it ({})",
            live_merged.join(", ")
        ));
    }

    None
}

/// Append every property name an ANF binding list assigns, including the ones
/// nested inside an `if` arm or a `loop` body — a nested write is just as much a
/// named slot the enclosing arm leaves behind.
fn collect_updated_props(bindings: &[ANFBinding], out: &mut Vec<String>) {
    for binding in bindings {
        match &binding.value {
            ANFValue::UpdateProp { name, .. } => {
                if !out.contains(name) {
                    out.push(name.clone());
                }
            }
            ANFValue::If {
                then, else_branch, ..
            } => {
                collect_updated_props(then, out);
                collect_updated_props(else_branch, out);
            }
            ANFValue::Loop { body, .. } => collect_updated_props(body, out),
            _ => {}
        }
    }
}

fn lower_for_statement(
    init: &Statement,
    condition: &Expression,
    update: &Statement,
    body: &[Statement],
    ctx: &mut LoweringContext,
    reads_after: &HashSet<String>,
) {
    // Resolve the loop's compile-time shape: start value, step direction, and
    // iteration count. Rúnar requires bounded loops, so all three must be
    // statically determinable (issue #121).
    let (start, step, count) = extract_loop_shape(init, condition, update);

    // Extract the iterator variable name
    let iter_var = if let Statement::VariableDecl { name, .. } = init {
        name.clone()
    } else {
        "_i".to_string()
    };

    // Lower body into sub-context. The body repeats, so every read anywhere in
    // it is a read that happens after any given statement inside it.
    let mut body_reads = reads_after.clone();
    for s in body {
        collect_statement_reads(s, &mut body_reads);
    }

    let mut body_ctx = ctx.sub_context();
    lower_statements_with_reads(body, &mut body_ctx, &body_reads);
    ctx.sync_counter(&body_ctx);

    ctx.emit(ANFValue::Loop {
        count,
        body: body_ctx.bindings,
        iter_var,
        start: bigint_to_json(&start),
        step,
    });
}

/// Resolve a for-statement's compile-time loop shape (issue #121).
///
/// Supports counting-up and counting-down loops:
///   for (let i = 0n; i < 10n; i++)     -> start 0,  step +1, count 10
///   for (let i = 1n; i <= 3n; i++)     -> start 1,  step +1, count 3
///   for (let i = 3n; i > 0n; i--)      -> start 3,  step -1, count 3
///   for (let i = 3n; i >= 1n; i--)     -> start 3,  step -1, count 3
///
/// The loop is unrolled `count` times; on iteration `i` the iterator holds
/// `start + i * step`. Start and bound must be compile-time integer literals.
///
/// This path is a hard guard for callers that skip validation; the normal
/// pipeline rejects unresolvable shapes in the validate pass first.
fn extract_loop_shape(
    init: &Statement,
    condition: &Expression,
    update: &Statement,
) -> (num_bigint::BigInt, i64, usize) {
    let start = match init {
        Statement::VariableDecl { init: init_expr, .. } => extract_bigint_value(init_expr),
        _ => None,
    };
    let start = match start {
        Some(s) => BigInt::from(s),
        None => panic!(
            "Cannot determine loop start at compile time. For-loop iterators must start at an integer literal."
        ),
    };

    let (op, bound) = match condition {
        Expression::BinaryExpr { op, right, .. } => match extract_bigint_value(right) {
            Some(b) => (op, BigInt::from(b)),
            None => panic!(
                "Cannot determine loop bound at compile time. For-loop bounds must be integer literals."
            ),
        },
        _ => panic!(
            "Cannot determine loop bound at compile time. For-loop bounds must be integer literals."
        ),
    };

    let step = extract_loop_step(condition, update);

    // Count = number of iterations before the condition first turns false.
    let count: BigInt = if step == 1 {
        match op {
            BinaryOp::Lt => &bound - &start,
            BinaryOp::Le => &bound - &start + 1,
            _ => panic!("For loop counting up (i++) must use '<' or '<=' (got '{:?}').", op),
        }
    } else {
        match op {
            BinaryOp::Gt => &start - &bound,
            BinaryOp::Ge => &start - &bound + 1,
            _ => panic!("For loop counting down (i--) must use '>' or '>=' (got '{:?}').", op),
        }
    };

    let count = count.to_i64().unwrap_or(0).max(0) as usize;
    (start, step, count)
}

/// Determine the iterator step direction (+1 / -1) from the for-statement's
/// update clause, falling back to the condition direction. Only unit steps are
/// supported; a non-unit update (e.g. `i += 2`) is out of the loop model.
fn extract_loop_step(condition: &Expression, update: &Statement) -> i64 {
    if let Statement::ExpressionStatement { expression, .. } = update {
        match expression {
            Expression::IncrementExpr { .. } => return 1,
            Expression::DecrementExpr { .. } => return -1,
            _ => {}
        }
    }
    // Fall back to the comparison direction for other unit-step spellings
    // (e.g. `i = i + 1n`): `<`/`<=` counts up, `>`/`>=` counts down.
    if let Expression::BinaryExpr { op, .. } = condition {
        if *op == BinaryOp::Gt || *op == BinaryOp::Ge {
            return -1;
        }
    }
    1
}

fn extract_bigint_value(expr: &Expression) -> Option<i128> {
    match expr {
        Expression::BigIntLiteral { value } => value.to_i128(),
        Expression::UnaryExpr { op, operand } if *op == UnaryOp::Neg => {
            extract_bigint_value(operand).map(|v| -v)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Expression lowering -- the heart of ANF conversion
//
// Matches the TypeScript lowerExprToRef exactly.
// ---------------------------------------------------------------------------

/// Lower an expression to ANF form and return the name of the temp variable
/// holding its value.
fn lower_expr_to_ref(expr: &Expression, ctx: &mut LoweringContext) -> String {
    match expr {
        Expression::BigIntLiteral { value } => ctx.emit(ANFValue::LoadConst {
            value: bigint_to_json(value),
        }),

        Expression::BoolLiteral { value } => ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::Bool(*value),
        }),

        Expression::ByteStringLiteral { value } => ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::String(value.clone()),
        }),

        Expression::Identifier { name } => lower_identifier(name, ctx),

        Expression::PropertyAccess { property } => {
            // Explicit `this.x`: a real contract property always wins, even when
            // a method param shares the name (issue #130). Now that declared
            // params are registered, the is_param branch below must not shadow a
            // stored property.
            if ctx.is_property(property) {
                return ctx.emit(ANFValue::LoadProp {
                    name: property.clone(),
                });
            }
            // this.txPreimage in StatefulSmartContract -> load_param (it's an
            // implicit injected param, not a stored property).
            if ctx.is_param(property) {
                return ctx.emit(ANFValue::LoadParam {
                    name: property.clone(),
                });
            }
            // this.x -> load_prop
            ctx.emit(ANFValue::LoadProp {
                name: property.clone(),
            })
        }

        Expression::MemberExpr { object, property } => lower_member_expr(object, property, ctx),

        Expression::BinaryExpr { op, left, right } => lower_binary_expr(op, left, right, ctx),

        Expression::UnaryExpr { op, operand } => lower_unary_expr(op, operand, ctx),

        Expression::CallExpr { callee, args, .. } => lower_call_expr(callee, args, ctx),

        Expression::TernaryExpr {
            condition,
            consequent,
            alternate,
        } => lower_ternary_expr(condition, consequent, alternate, ctx),

        Expression::IndexAccess { object, index } => lower_index_access(object, index, ctx),

        Expression::IncrementExpr { operand, prefix } => {
            lower_increment_expr(operand, *prefix, ctx)
        }

        Expression::DecrementExpr { operand, prefix } => {
            lower_decrement_expr(operand, *prefix, ctx)
        }

        Expression::ArrayLiteral { elements } => {
            // Lower each element to a reference, then emit an array_literal ANF node.
            let element_refs: Vec<String> = elements
                .iter()
                .map(|elem| lower_expr_to_ref(elem, ctx))
                .collect();
            ctx.emit(ANFValue::ArrayLiteral {
                elements: element_refs,
            })
        }
    }
}

/// Lower an identifier. Matches the TS reference's lowerIdentifier exactly:
/// 1. 'this' -> load_const "@this"
/// 2. isParam(name) -> load_param (but isParam always false since addParam never called)
/// 3. isLocal(name) -> return name directly (reference the local variable)
/// 4. isProperty(name) -> load_prop
/// 5. default -> load_param (emitted EVERY time, no caching)
fn lower_identifier(name: &str, ctx: &mut LoweringContext) -> String {
    // 'this' is not a value in ANF
    if name == "this" {
        return ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::String("@this".to_string()),
        });
    }

    // Param alias takes precedence over normal param lookup. Set when
    // a private method's body is being inlined into this context —
    // the private's param names map to the caller's arg refs.
    if let Some(alias) = ctx.get_param_alias(name) {
        return alias.clone();
    }

    // Check if it's a registered parameter (e.g. txPreimage for StatefulSmartContract)
    if ctx.is_param(name) {
        return ctx.emit(ANFValue::LoadParam {
            name: name.to_string(),
        });
    }

    // Check if it's a local variable -- reference it directly
    // (or use its alias if reassigned by an if-statement)
    if ctx.is_local(name) {
        return ctx
            .get_local_alias(name)
            .cloned()
            .unwrap_or_else(|| name.to_string());
    }

    // Check if it's a contract property
    if ctx.is_property(name) {
        return ctx.emit(ANFValue::LoadProp {
            name: name.to_string(),
        });
    }

    // Default: treat as parameter (this is how params get loaded lazily)
    // Emitted EVERY time, no caching
    ctx.emit(ANFValue::LoadParam {
        name: name.to_string(),
    })
}

fn lower_member_expr(
    object: &Expression,
    property: &str,
    ctx: &mut LoweringContext,
) -> String {
    // this.x -> load_prop (or load_param for implicit params like txPreimage)
    if let Expression::Identifier { name } = object {
        if name == "this" {
            // Explicit `this.x`: a real contract property always wins, even
            // when a method param shares the name (issue #130). Only fall
            // through to load_param for implicit injected params (txPreimage)
            // that are NOT stored properties.
            if ctx.is_property(property) {
                return ctx.emit(ANFValue::LoadProp {
                    name: property.to_string(),
                });
            }
            if ctx.is_param(property) {
                return ctx.emit(ANFValue::LoadParam {
                    name: property.to_string(),
                });
            }
            return ctx.emit(ANFValue::LoadProp {
                name: property.to_string(),
            });
        }
    }

    // SigHash.ALL etc. -> load constant
    if let Expression::Identifier { name } = object {
        if name == "SigHash" {
            let val = match property {
                "ALL" => 0x01i64,
                "NONE" => 0x02,
                "SINGLE" => 0x03,
                "FORKID" => 0x40,
                "ANYONECANPAY" => 0x80,
                _ => 0,
            };
            return ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from(val)),
            });
        }
    }

    // General member access
    let obj_ref = lower_expr_to_ref(object, ctx);
    ctx.emit(ANFValue::MethodCall {
        object: obj_ref,
        method: property.to_string(),
        args: Vec::new(),
    })
}

fn lower_binary_expr(
    op: &BinaryOp,
    left: &Expression,
    right: &Expression,
    ctx: &mut LoweringContext,
) -> String {
    let left_ref = lower_expr_to_ref(left, ctx);
    let right_ref = lower_expr_to_ref(right, ctx);

    // For equality operators, annotate with operand type so stack lowering
    // can choose OP_EQUAL vs OP_NUMEQUAL.
    // For +, annotate byte-typed operands so stack lowering can emit OP_CAT.
    // For bitwise &, |, ^, annotate byte-typed operands.
    let result_type = if op.as_str() == "===" || op.as_str() == "!==" {
        if is_byte_typed_expr(left, ctx) || is_byte_typed_expr(right, ctx) {
            Some("bytes".to_string())
        } else {
            None
        }
    } else if op.as_str() == "&" || op.as_str() == "|" || op.as_str() == "^" {
        if is_byte_typed_expr(left, ctx) || is_byte_typed_expr(right, ctx) {
            Some("bytes".to_string())
        } else {
            None
        }
    } else {
        None
    };

    ctx.emit(ANFValue::BinOp {
        op: op.as_str().to_string(),
        left: left_ref,
        right: right_ref,
        result_type,
    })
}

fn lower_unary_expr(
    op: &UnaryOp,
    operand: &Expression,
    ctx: &mut LoweringContext,
) -> String {
    let operand_ref = lower_expr_to_ref(operand, ctx);
    // For ~, annotate byte-typed operands so downstream passes know the result is bytes.
    let result_type = if op.as_str() == "~" && is_byte_typed_expr(operand, ctx) {
        Some("bytes".to_string())
    } else {
        None
    };
    ctx.emit(ANFValue::UnaryOp {
        op: op.as_str().to_string(),
        operand: operand_ref,
        result_type,
    })
}

fn lower_call_expr(
    callee: &Expression,
    args: &[Expression],
    ctx: &mut LoweringContext,
) -> String {
    // super(...) call
    if let Expression::Identifier { name } = callee {
        if name == "super" {
            let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
            return ctx.emit(ANFValue::Call {
                func: "super".to_string(),
                args: arg_refs,
            });
        }
    }

    // assert(expr) -> assert value
    if let Expression::Identifier { name } = callee {
        if name == "assert" {
            if !args.is_empty() {
                let value_ref = lower_expr_to_ref(&args[0], ctx);
                return ctx.emit(ANFValue::Assert { value: value_ref, is_auto_injected_state_check: false });
            }
            let false_ref = ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Bool(false),
            });
            return ctx.emit(ANFValue::Assert { value: false_ref, is_auto_injected_state_check: false });
        }
    }

    // checkPreimage(preimage) -> special node
    if let Expression::Identifier { name } = callee {
        if name == "checkPreimage" {
            if !args.is_empty() {
                let preimage_ref = lower_expr_to_ref(&args[0], ctx);
                return ctx.emit(ANFValue::CheckPreimage {
                    preimage: preimage_ref,
                    // Issue #123: honour the method's declared @sighash on
                    // manual checkPreimage calls (None = default ALL|FORKID).
                    sighash_flag: ctx.sighash_flag,
                });
            }
        }
    }

    // extractPrevOutputScript(inputIndex_literal, expectedScriptHash) -> ByteString
    // extractPrevOutputScript(inputIndex_literal, expectedScriptPrefixHash, prefixLen_literal) -> ByteString
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
    //   pushdata tail free to vary. Required for intent-template matching
    //   (BSVM Mode 3 permissionless step-in).
    if let Expression::Identifier { name } = callee {
        if name == "extractPrevOutputScript" {
            if args.len() != 2 && args.len() != 3 {
                return ctx.emit(ANFValue::LoadConst {
                    value: serde_json::Value::String(String::new()),
                });
            }
            let idx = match &args[0] {
                Expression::BigIntLiteral { value } => match value.to_i128() {
                    Some(v) => v,
                    None => {
                        return ctx.emit(ANFValue::LoadConst {
                            value: serde_json::Value::String(String::new()),
                        });
                    }
                },
                _ => {
                    return ctx.emit(ANFValue::LoadConst {
                        value: serde_json::Value::String(String::new()),
                    });
                }
            };
            let param_name = format!("_prevOutScript_{}", idx);
            ctx.method_scope
                .borrow_mut()
                .record_auto_injected_param(&param_name, "ByteString");
            ctx.add_param(&param_name);
            let witness_ref = ctx.emit(ANFValue::LoadParam {
                name: param_name.clone(),
            });
            let expected_hash_ref = lower_expr_to_ref(&args[1], ctx);

            // Determine which bytes to hash: full witness (2-arg) or prefix
            // (3-arg). The substr happens at script-execution time; the
            // literal prefixLen is baked into the emitted Stack-IR.
            let bytes_to_hash_ref = if args.len() == 3 {
                let prefix_len = match &args[2] {
                    Expression::BigIntLiteral { value } => match value.to_i128() {
                        Some(v) => v,
                        None => {
                            return ctx.emit(ANFValue::LoadConst {
                                value: serde_json::Value::String(String::new()),
                            });
                        }
                    },
                    _ => {
                        return ctx.emit(ANFValue::LoadConst {
                            value: serde_json::Value::String(String::new()),
                        });
                    }
                };
                let zero_ref = ctx.emit(ANFValue::LoadConst {
                    value: serde_json::Value::Number(serde_json::Number::from(0i64)),
                });
                let prefix_len_ref = ctx.emit(ANFValue::LoadConst {
                    value: serde_json::Value::Number(
                        serde_json::Number::from(prefix_len as i64),
                    ),
                });
                ctx.emit(ANFValue::Call {
                    func: "substr".to_string(),
                    args: vec![witness_ref.clone(), zero_ref, prefix_len_ref],
                })
            } else {
                witness_ref.clone()
            };

            let actual_hash_ref = ctx.emit(ANFValue::Call {
                func: "hash256".to_string(),
                args: vec![bytes_to_hash_ref],
            });
            let eq_ref = ctx.emit(ANFValue::BinOp {
                op: "===".to_string(),
                left: actual_hash_ref,
                right: expected_hash_ref,
                result_type: Some("bytes".to_string()),
            });
            ctx.emit(ANFValue::Assert { value: eq_ref, is_auto_injected_state_check: false });
            return witness_ref;
        }
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
    if let Expression::Identifier { name } = callee {
        if name == "requireOutputP2PKH" {
            if args.len() != 3 {
                return ctx.emit(ANFValue::LoadConst {
                    value: serde_json::Value::String(String::new()),
                });
            }
            let idx = match &args[0] {
                Expression::BigIntLiteral { value } => match value.to_i128() {
                    Some(v) => v,
                    None => {
                        return ctx.emit(ANFValue::LoadConst {
                            value: serde_json::Value::String(String::new()),
                        });
                    }
                },
                _ => {
                    return ctx.emit(ANFValue::LoadConst {
                        value: serde_json::Value::String(String::new()),
                    });
                }
            };

            ctx.method_scope
                .borrow_mut()
                .record_auto_injected_param("_serialisedOutputs", "ByteString");
            ctx.add_param("_serialisedOutputs");

            // Emit the hashOutputs(preimage) check exactly once per method.
            let need_hash_check = {
                let mut scope = ctx.method_scope.borrow_mut();
                if !scope.did_emit_hash_outputs_check {
                    scope.did_emit_hash_outputs_check = true;
                    true
                } else {
                    false
                }
            };
            if need_hash_check {
                let serialised_ref = ctx.emit(ANFValue::LoadParam {
                    name: "_serialisedOutputs".to_string(),
                });
                let actual_out_hash_ref = ctx.emit(ANFValue::Call {
                    func: "hash256".to_string(),
                    args: vec![serialised_ref],
                });
                let preimage_ref = ctx.emit(ANFValue::LoadParam {
                    name: "txPreimage".to_string(),
                });
                let expected_out_hash_ref = ctx.emit(ANFValue::Call {
                    func: "extractOutputHash".to_string(),
                    args: vec![preimage_ref],
                });
                let hash_eq_ref = ctx.emit(ANFValue::BinOp {
                    op: "===".to_string(),
                    left: actual_out_hash_ref,
                    right: expected_out_hash_ref,
                    result_type: Some("bytes".to_string()),
                });
                ctx.emit(ANFValue::Assert { value: hash_eq_ref, is_auto_injected_state_check: false });
            }

            // Lower the user-supplied args (pubkeyHash, amount).
            let pubkey_hash_ref = lower_expr_to_ref(&args[1], ctx);
            let amount_ref = lower_expr_to_ref(&args[2], ctx);

            // Construct expected P2PKH output bytes:
            //   <amount: 8-byte LE> ‖ 0x19 0x76 0xa9 0x14 ‖ <pubkeyHash: 20 bytes> ‖ 0x88 0xac
            let eight_ref = ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from(8i64)),
            });
            let amount_bytes_ref = ctx.emit(ANFValue::Call {
                func: "num2bin".to_string(),
                args: vec![amount_ref, eight_ref],
            });
            // 0x19 0x76 0xa9 0x14 — script length byte + OP_DUP OP_HASH160 OP_PUSH20
            let prefix_ref = ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::String("1976a914".to_string()),
            });
            // 0x88 0xac — OP_EQUALVERIFY OP_CHECKSIG
            let suffix_ref = ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::String("88ac".to_string()),
            });
            let cat1_ref = ctx.emit(ANFValue::Call {
                func: "cat".to_string(),
                args: vec![amount_bytes_ref, prefix_ref],
            });
            let cat2_ref = ctx.emit(ANFValue::Call {
                func: "cat".to_string(),
                args: vec![cat1_ref, pubkey_hash_ref],
            });
            let expected_output_ref = ctx.emit(ANFValue::Call {
                func: "cat".to_string(),
                args: vec![cat2_ref, suffix_ref],
            });

            // Substring extract at idx*34 length 34, assert equal.
            let serialised_ref = ctx.emit(ANFValue::LoadParam {
                name: "_serialisedOutputs".to_string(),
            });
            let offset_ref = ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from((idx as i64) * 34)),
            });
            let length_ref = ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from(34i64)),
            });
            let extracted_ref = ctx.emit(ANFValue::Call {
                func: "substr".to_string(),
                args: vec![serialised_ref, offset_ref, length_ref],
            });
            let out_eq_ref = ctx.emit(ANFValue::BinOp {
                op: "===".to_string(),
                left: extracted_ref,
                right: expected_output_ref,
                result_type: Some("bytes".to_string()),
            });
            return ctx.emit(ANFValue::Assert { value: out_eq_ref, is_auto_injected_state_check: false });
        }
    }

    // currentBlockHeight() -> bigint. Pure source-level desugar to
    // extractLocktime(this.txPreimage). Only valid in StatefulSmartContract
    // methods (typecheck enforces). No new ANF kind or stack codegen needed.
    if let Expression::Identifier { name } = callee {
        if name == "currentBlockHeight" {
            let preimage_ref = ctx.emit(ANFValue::LoadParam {
                name: "txPreimage".to_string(),
            });
            return ctx.emit(ANFValue::Call {
                func: "extractLocktime".to_string(),
                args: vec![preimage_ref],
            });
        }
    }

    // this.addOutput(satoshis, val1, val2, ...) -> special node.
    // Mirrors flattenAddOutputArgs in 04-anf-lower.ts: when addOutput is
    // called as `this.addOutput(satoshis, .{ v1, v2, ... })` (the surface
    // form Zig / Move tuple syntax produce), unwrap the trailing array
    // literal so each element becomes an individual state value.
    if let Expression::PropertyAccess { property } = callee {
        if property == "addOutput" {
            let flat_args = flatten_add_output_args(args);
            let arg_refs: Vec<String> = flat_args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
            let satoshis = arg_refs.first().cloned().unwrap_or_default();
            let state_values = if arg_refs.len() > 1 { arg_refs[1..].to_vec() } else { Vec::new() };
            let r = ctx.emit(ANFValue::AddOutput { satoshis, state_values, preimage: String::new() });
            ctx.add_output_refs.push(r.clone());
            return r;
        }
    }
    // this.addOutput(satoshis, val1, val2, ...) -> special node (via MemberExpr with this)
    if let Expression::MemberExpr { object, property } = callee {
        if let Expression::Identifier { name } = object.as_ref() {
            if name == "this" && property == "addOutput" {
                let flat_args = flatten_add_output_args(args);
                let arg_refs: Vec<String> = flat_args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
                let satoshis = arg_refs.first().cloned().unwrap_or_default();
                let state_values = if arg_refs.len() > 1 { arg_refs[1..].to_vec() } else { Vec::new() };
                let r = ctx.emit(ANFValue::AddOutput { satoshis, state_values, preimage: String::new() });
                ctx.add_output_refs.push(r.clone());
                return r;
            }
        }
    }

    // this.addRawOutput(satoshis, scriptBytes) -> special node (via PropertyAccess)
    if let Expression::PropertyAccess { property } = callee {
        if property == "addRawOutput" {
            let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
            let satoshis = arg_refs.first().cloned().unwrap_or_default();
            let script_bytes = if arg_refs.len() > 1 { arg_refs[1].clone() } else { String::new() };
            let r = ctx.emit(ANFValue::AddRawOutput { satoshis, script_bytes });
            ctx.add_output_refs.push(r.clone());
            return r;
        }
    }
    // this.addRawOutput(satoshis, scriptBytes) -> special node (via MemberExpr with this)
    if let Expression::MemberExpr { object, property } = callee {
        if let Expression::Identifier { name } = object.as_ref() {
            if name == "this" && property == "addRawOutput" {
                let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
                let satoshis = arg_refs.first().cloned().unwrap_or_default();
                let script_bytes = if arg_refs.len() > 1 { arg_refs[1].clone() } else { String::new() };
                let r = ctx.emit(ANFValue::AddRawOutput { satoshis, script_bytes });
                ctx.add_output_refs.push(r.clone());
                return r;
            }
        }
    }

    // this.addDataOutput(satoshis, scriptBytes) -> special node (via PropertyAccess).
    // Same wire shape as addRawOutput, but tracked separately so that the
    // continuation-hash composition can place data outputs AFTER state outputs
    // and BEFORE the change output.
    if let Expression::PropertyAccess { property } = callee {
        if property == "addDataOutput" {
            let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
            let satoshis = arg_refs.first().cloned().unwrap_or_default();
            let script_bytes = if arg_refs.len() > 1 { arg_refs[1].clone() } else { String::new() };
            let r = ctx.emit(ANFValue::AddDataOutput { satoshis, script_bytes });
            ctx.add_data_output_refs.push(r.clone());
            return r;
        }
    }
    // this.addDataOutput(satoshis, scriptBytes) -> special node (via MemberExpr with this)
    if let Expression::MemberExpr { object, property } = callee {
        if let Expression::Identifier { name } = object.as_ref() {
            if name == "this" && property == "addDataOutput" {
                let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
                let satoshis = arg_refs.first().cloned().unwrap_or_default();
                let script_bytes = if arg_refs.len() > 1 { arg_refs[1].clone() } else { String::new() };
                let r = ctx.emit(ANFValue::AddDataOutput { satoshis, script_bytes });
                ctx.add_data_output_refs.push(r.clone());
                return r;
            }
        }
    }

    // this.getStateScript() -> special node (via PropertyAccess)
    if let Expression::PropertyAccess { property } = callee {
        if property == "getStateScript" {
            return ctx.emit(ANFValue::GetStateScript {});
        }
    }
    // this.getStateScript() -> special node (via MemberExpr)
    if let Expression::MemberExpr { object, property } = callee {
        if let Expression::Identifier { name } = object.as_ref() {
            if name == "this" && property == "getStateScript" {
                return ctx.emit(ANFValue::GetStateScript {});
            }
        }
    }

    // this.method(...) -> method_call (via PropertyAccess), or inlined
    // if the target is a private method with continuation-relevant
    // side effects.
    if let Expression::PropertyAccess { property } = callee {
        let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
        if ctx.should_inline_private(property) {
            return inline_private_method_call(property, &arg_refs, ctx);
        }
        let this_ref = ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::String("@this".to_string()),
        });
        return ctx.emit(ANFValue::MethodCall {
            object: this_ref,
            method: property.clone(),
            args: arg_refs,
        });
    }

    // this.method(...) -> method_call (via MemberExpr with this)
    if let Expression::MemberExpr { object, property } = callee {
        if let Expression::Identifier { name } = object.as_ref() {
            if name == "this" {
                let arg_refs: Vec<String> =
                    args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
                if ctx.should_inline_private(property) {
                    return inline_private_method_call(property, &arg_refs, ctx);
                }
                let this_ref = ctx.emit(ANFValue::LoadConst {
                    value: serde_json::Value::String("@this".to_string()),
                });
                return ctx.emit(ANFValue::MethodCall {
                    object: this_ref,
                    method: property.clone(),
                    args: arg_refs,
                });
            }
        }
    }

    // asm({...}) compiler intrinsic — the parser has already normalised the
    // object-literal argument into three positional args
    // (body, in_arity, out_arity). Lower it to a single opaque raw_script ANF
    // binding; the hex body passes through unchanged. Diagnostics for
    // malformed args were already pushed by the validator — here we
    // defensively coerce missing values to safe defaults.
    if let Expression::Identifier { name } = callee {
        if name == "asm" {
            let mut bytes = String::new();
            let mut in_arity: usize = 0;
            let mut out_arity: usize = 1;
            if let Some(Expression::ByteStringLiteral { value }) = args.get(0) {
                bytes = value.clone();
            }
            if let Some(Expression::BigIntLiteral { value }) = args.get(1) {
                in_arity = value.to_usize().unwrap_or(0);
            }
            if let Some(Expression::BigIntLiteral { value }) = args.get(2) {
                out_arity = value.to_usize().unwrap_or(1);
            }
            return ctx.emit(ANFValue::RawScript {
                bytes,
                in_arity,
                out_arity,
            });
        }
    }

    // Direct function call: sha256(x), checkSig(sig, pk), etc.
    if let Expression::Identifier { name } = callee {
        let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
        // Bare identifier calls that match a private method on the contract
        // (e.g. Move's `require_owner(contract, sig)` which the parser strips
        // to `requireOwner(sig)`) must be routed through the same inlining path
        // as `this.requireOwner(sig)` so downstream stack lowering can inline
        // the body. This keeps .runar.move, .runar.go, and .runar.ts lowering
        // in sync.
        if ctx.is_private_method(name) {
            if ctx.should_inline_private(name) {
                return inline_private_method_call(name, &arg_refs, ctx);
            }
            let this_ref = ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::String("@this".to_string()),
            });
            return ctx.emit(ANFValue::MethodCall {
                object: this_ref,
                method: name.clone(),
                args: arg_refs,
            });
        }
        return ctx.emit(ANFValue::Call {
            func: name.clone(),
            args: arg_refs,
        });
    }

    // General call expression
    let callee_ref = lower_expr_to_ref(callee, ctx);
    let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
    ctx.emit(ANFValue::MethodCall {
        object: callee_ref,
        method: "call".to_string(),
        args: arg_refs,
    })
}

/// Lower one arm of a ternary, guaranteeing the arm ENDS with the binding that
/// holds its result.
///
/// NEW-016: `lower_expr_to_ref` returns an existing ref without emitting
/// anything when the arm is a bare identifier — `g ? f : c === 0n` produced
/// `then: []`, an `if` arm with no bindings at all. Stack lowering reads an
/// arm's result off its stack effect, so a +0 arm has no result to adopt and
/// the depth reconcile padded the shortfall with an EMPTY push. The contract
/// compiled clean, the AST interpreter accepted it, and the real engine
/// rejected the spend with "OP_VERIFY requires the top stack value to be
/// truthy" over a stack of `[01, ]` — the arm's `true` replaced by an empty
/// (false) value. An ordinary contract deployed to a permanently unspendable
/// UTXO.
///
/// Aliasing through `load_const "@ref:"` — the same idiom `let x = y` and the
/// increment/decrement lowerings already use — makes the arm's stack effect +1
/// and copies the parent slot instead of trying to move it. The alias is only
/// emitted when the result was NOT produced inside the arm, so every arm that
/// already ended on its own result keeps its exact bytes.
fn lower_ternary_arm(expr: &Expression, arm_ctx: &mut LoweringContext) {
    let ref_name = lower_expr_to_ref(expr, arm_ctx);
    let ends_on_result = arm_ctx
        .bindings
        .last()
        .is_some_and(|last| last.name == ref_name);
    if !ends_on_result {
        arm_ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::String(format!("@ref:{}", ref_name)),
        });
    }
}

fn lower_ternary_expr(
    condition: &Expression,
    consequent: &Expression,
    alternate: &Expression,
    ctx: &mut LoweringContext,
) -> String {
    let cond_ref = lower_expr_to_ref(condition, ctx);

    let mut then_ctx = ctx.sub_context();
    lower_ternary_arm(consequent, &mut then_ctx);
    ctx.sync_counter(&then_ctx);

    let mut else_ctx = ctx.sub_context();
    lower_ternary_arm(alternate, &mut else_ctx);
    ctx.sync_counter(&else_ctx);

    ctx.emit(ANFValue::If {
        cond: cond_ref,
        then: then_ctx.bindings,
        else_branch: else_ctx.bindings,
        results: Vec::new(),
    })
}

fn lower_index_access(
    object: &Expression,
    index: &Expression,
    ctx: &mut LoweringContext,
) -> String {
    let obj_ref = lower_expr_to_ref(object, ctx);
    let index_ref = lower_expr_to_ref(index, ctx);

    ctx.emit(ANFValue::Call {
        func: "__array_access".to_string(),
        args: vec![obj_ref, index_ref],
    })
}

fn lower_increment_expr(
    operand: &Expression,
    prefix: bool,
    ctx: &mut LoweringContext,
) -> String {
    let operand_ref = lower_expr_to_ref(operand, ctx);
    let one_ref = ctx.emit(ANFValue::LoadConst {
        value: serde_json::Value::Number(serde_json::Number::from(1i64)),
    });
    let result = ctx.emit(ANFValue::BinOp {
        op: "+".to_string(),
        left: operand_ref.clone(),
        right: one_ref,
        result_type: None,
    });

    // If the operand is a named variable, update it
    if let Expression::Identifier { name } = operand {
        ctx.emit_named(
            name,
            ANFValue::LoadConst {
                value: serde_json::Value::String(format!("@ref:{}", result)),
            },
        );
    }
    if let Expression::PropertyAccess { property } = operand {
        ctx.emit(ANFValue::UpdateProp {
            name: property.clone(),
            value: result.clone(),
        });
    }

    if prefix {
        result
    } else {
        operand_ref
    }
}

fn lower_decrement_expr(
    operand: &Expression,
    prefix: bool,
    ctx: &mut LoweringContext,
) -> String {
    let operand_ref = lower_expr_to_ref(operand, ctx);
    let one_ref = ctx.emit(ANFValue::LoadConst {
        value: serde_json::Value::Number(serde_json::Number::from(1i64)),
    });
    let result = ctx.emit(ANFValue::BinOp {
        op: "-".to_string(),
        result_type: None,
        left: operand_ref.clone(),
        right: one_ref,
    });

    // If the operand is a named variable, update it
    if let Expression::Identifier { name } = operand {
        ctx.emit_named(
            name,
            ANFValue::LoadConst {
                value: serde_json::Value::String(format!("@ref:{}", result)),
            },
        );
    }
    if let Expression::PropertyAccess { property } = operand {
        ctx.emit(ANFValue::UpdateProp {
            name: property.clone(),
            value: result.clone(),
        });
    }

    if prefix {
        result
    } else {
        operand_ref
    }
}

// ---------------------------------------------------------------------------
// Type inference helpers for equality semantics
// ---------------------------------------------------------------------------

/// Byte-typed primitive names -- values that are already byte sequences.
const BYTE_TYPES: &[&str] = &[
    "ByteString", "PubKey", "Sig", "Sha256", "Ripemd160", "Addr", "SigHashPreimage",
    "RabinSig", "RabinPubKey", "Point", "P256Point", "P384Point",
];

/// Builtin functions that return byte-typed values.
const BYTE_RETURNING_FUNCTIONS: &[&str] = &[
    "sha256", "ripemd160", "hash160", "hash256", "cat", "num2bin", "int2str",
    "reverseBytes", "substr", "left", "right",
    "ecAdd", "ecMul", "ecMulGen", "ecNegate", "ecMakePoint", "ecEncodeCompressed",
    "sha256Compress", "sha256Finalize", "blake3Compress", "blake3Hash",
    "p256Add", "p256Mul", "p256MulGen", "p256Negate", "p256EncodeCompressed",
    "p384Add", "p384Mul", "p384MulGen", "p384Negate", "p384EncodeCompressed",
];

/// Determine whether an expression is byte-typed (ByteString, PubKey, Sig, etc.).
/// This is a best-effort heuristic used to annotate equality operators.
fn is_byte_typed_expr(expr: &Expression, ctx: &LoweringContext) -> bool {
    match expr {
        Expression::ByteStringLiteral { .. } => true,

        Expression::Identifier { name } => {
            // Check if it's a parameter or property with a byte type
            if let Some(t) = get_param_type(name, ctx) {
                if BYTE_TYPES.contains(&t.as_str()) {
                    return true;
                }
            }
            if let Some(t) = get_property_type(name, ctx) {
                if BYTE_TYPES.contains(&t.as_str()) {
                    return true;
                }
            }
            if ctx.local_byte_vars.contains(name.as_str()) {
                return true;
            }
            false
        }

        Expression::PropertyAccess { property } => {
            if let Some(t) = get_property_type(property, ctx) {
                if BYTE_TYPES.contains(&t.as_str()) {
                    return true;
                }
            }
            false
        }

        Expression::MemberExpr { object, property } => {
            if let Expression::Identifier { name } = object.as_ref() {
                if name == "this" {
                    if let Some(t) = get_property_type(property, ctx) {
                        if BYTE_TYPES.contains(&t.as_str()) {
                            return true;
                        }
                    }
                }
            }
            false
        }

        Expression::CallExpr {
            callee,
            asm_return_type,
            ..
        } => {
            if let Expression::Identifier { name } = callee.as_ref() {
                // Expression-form asm<ByteString>({...}) yields a byte value.
                if name == "asm" {
                    return asm_return_type.as_deref() == Some("ByteString");
                }
                if BYTE_RETURNING_FUNCTIONS.contains(&name.as_str()) {
                    return true;
                }
            }
            false
        }

        _ => false,
    }
}

/// Look up the type of a parameter by name within the CURRENT method scope.
/// Method-scoped (issue #34): reads only the params registered for the method
/// (or constructor) currently being lowered, so a local in one method cannot
/// falsely match a same-named parameter of a different method.
fn get_param_type(name: &str, ctx: &LoweringContext) -> Option<String> {
    ctx.param_types.get(name).cloned()
}

/// Look up the type of a contract property by name.
fn get_property_type(name: &str, ctx: &LoweringContext) -> Option<String> {
    for p in &ctx.contract.properties {
        if p.name == name {
            return Some(type_node_to_string(&p.prop_type));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn type_node_to_string(node: &TypeNode) -> String {
    match node {
        TypeNode::Primitive(name) => name.as_str().to_string(),
        TypeNode::FixedArray { element, length } => {
            format!("FixedArray<{}, {}>", type_node_to_string(element), length)
        }
        TypeNode::Custom(name) => name.clone(),
    }
}

// ---------------------------------------------------------------------------
// inline_private_method_call — ANF-level inlining of private helpers
// ---------------------------------------------------------------------------

/// Lower a private method's body directly into the caller's context.
///
/// Used when the private has continuation-relevant side effects (state
/// mutation, addOutput, addRawOutput, addDataOutput) so the helper's
/// emitted ANF nodes register output refs on the caller. Caller's arg
/// refs are mapped onto the private's parameter names via
/// `push_param_alias`. While the private's body lowers, any
/// identifier expression matching one of those param names resolves
/// to the caller's ref. The aliases are popped afterwards so
/// subsequent lowering in the caller's body sees its own scope.
///
/// Recursion across private helpers is forbidden by validation, so
/// this always terminates. Nested inlining (private A calls private
/// B) works naturally: when we lower A's body and hit the call to B,
/// the same dispatch path runs and inlines B too.
fn inline_private_method_call(
    method_name: &str,
    arg_refs: &[String],
    ctx: &mut LoweringContext,
) -> String {
    // Snapshot the method body + param names before mutating the
    // context (Rust's borrow checker won't let us hold a &MethodNode
    // and mutate ctx simultaneously).
    let (params, body): (Vec<String>, Vec<Statement>) = match ctx.get_private_method(method_name) {
        Some(m) => (m.params.iter().map(|p| p.name.clone()).collect(), m.body.clone()),
        None => {
            // Should not happen — caller checked should_inline_private,
            // which requires the method to exist. Fall back to a
            // method_call so the stack lowering pass surfaces a clear
            // error.
            let this_ref = ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::String("@this".to_string()),
            });
            return ctx.emit(ANFValue::MethodCall {
                object: this_ref,
                method: method_name.to_string(),
                args: arg_refs.to_vec(),
            });
        }
    };

    // Bind caller arg refs to the private's parameter names.
    let mut aliased: Vec<String> = Vec::new();
    for (i, param_name) in params.iter().enumerate() {
        if i >= arg_refs.len() {
            break;
        }
        ctx.push_param_alias(param_name, &arg_refs[i]);
        aliased.push(param_name.clone());
    }

    let start_index = ctx.bindings.len();
    lower_statements(&body, ctx);
    let end_index = ctx.bindings.len();

    // Pop aliases in reverse order so nested inlines compose
    // correctly.
    for name in aliased.iter().rev() {
        ctx.pop_param_alias(name);
    }

    // Method's "return value" is the last binding emitted by the
    // body. Void methods (e.g., a private helper that just calls
    // addOutput) still produce a binding which the caller
    // expression-statement path will discard.
    if end_index > start_index {
        return ctx.bindings[end_index - 1].name.clone();
    }
    // Empty body — emit a load_const placeholder so the caller has
    // a ref.
    ctx.emit(ANFValue::LoadConst {
        value: serde_json::Value::String("@void".to_string()),
    })
}

// ---------------------------------------------------------------------------
// liftBranchUpdateProps — flatten nested if-else chains with update_prop
// ---------------------------------------------------------------------------
//
// Mirrors the TypeScript reference compiler's `liftBranchUpdateProps` function
// in 04-anf-lower.ts. When an if-else chain has update_prop as the last binding
// in each branch (e.g., placeMove dispatching by position), this transform
// flattens the nesting into a flat series of conditional if-expressions +
// top-level update_prop calls. This is critical for the stack lowering pass,
// which cannot handle deeply nested if-else with update_prop correctly.

struct UpdateBranch {
    cond_setup_bindings: Vec<ANFBinding>,
    cond_ref: Option<String>,
    prop_name: String,
    value_bindings: Vec<ANFBinding>,
    #[allow(dead_code)]
    value_ref: String,
}

/// Find the max temp index (e.g. t47 → 47) in a binding tree.
fn max_temp_index(bindings: &[ANFBinding]) -> i64 {
    let mut max = -1i64;
    for b in bindings {
        if b.name.starts_with('t') {
            if let Ok(n) = b.name[1..].parse::<i64>() {
                if n > max {
                    max = n;
                }
            }
        }
        match &b.value {
            ANFValue::If { then, else_branch, .. } => {
                let t = max_temp_index(then);
                if t > max { max = t; }
                let e = max_temp_index(else_branch);
                if e > max { max = e; }
            }
            ANFValue::Loop { body, .. } => {
                let l = max_temp_index(body);
                if l > max { max = l; }
            }
            _ => {}
        }
    }
    max
}

/// Check if a binding's value is side-effect-free.
fn is_side_effect_free(value: &ANFValue) -> bool {
    matches!(
        value,
        ANFValue::LoadProp { .. }
            | ANFValue::LoadParam { .. }
            | ANFValue::LoadConst { .. }
            | ANFValue::BinOp { .. }
            | ANFValue::UnaryOp { .. }
    )
}

fn all_bindings_side_effect_free(bindings: &[ANFBinding]) -> bool {
    bindings.iter().all(|b| is_side_effect_free(&b.value))
}

/// Extract the update_prop target from a branch's bindings.
/// Returns (prop_name, value_bindings_before_update, value_ref) if the last
/// binding is update_prop and all preceding bindings are side-effect-free.
fn extract_branch_update(bindings: &[ANFBinding]) -> Option<(String, Vec<ANFBinding>, String)> {
    if bindings.is_empty() {
        return None;
    }
    let last = &bindings[bindings.len() - 1];
    if let ANFValue::UpdateProp { name: prop_name, value: val_ref } = &last.value {
        let value_bindings = bindings[..bindings.len() - 1].to_vec();
        if !all_bindings_side_effect_free(&value_bindings) {
            return None;
        }
        Some((prop_name.clone(), value_bindings, val_ref.clone()))
    } else {
        None
    }
}

/// Check if an else branch is just `assert(false)` — unreachable dead code.
fn is_assert_false_else(bindings: &[ANFBinding]) -> bool {
    if bindings.is_empty() {
        return false;
    }
    let last = &bindings[bindings.len() - 1];
    if let ANFValue::Assert { value: assert_ref, .. } = &last.value {
        // Find the binding that assert_ref references
        for b in bindings {
            if b.name == *assert_ref {
                if let ANFValue::LoadConst { value: v } = &b.value {
                    return v == &serde_json::Value::Bool(false);
                }
            }
        }
    }
    false
}

/// An arm with its declared-results block removed.
///
/// `append_branch_results` adds exactly `2 * results.len()` trailing bindings to
/// each arm of an `if` that declares results. They are a materialisation
/// mechanism, not program logic, and they hide the arm's real shape from this
/// pass. A dispatch chain's deepest `if` is nested by definition, so it declares
/// results; without this the enclosing chain stops being recognised and
/// TicTacToe's position dispatch loses the C20 lift (an unspendable script).
fn strip_declared_results<'b>(
    bindings: &'b [ANFBinding],
    results: &[String],
) -> &'b [ANFBinding] {
    let n = results.len();
    if n == 0 {
        return bindings;
    }
    let cut = bindings.len().saturating_sub(2 * n);
    &bindings[..cut]
}

/// Recursively collect update branches from a nested if-else chain.
fn collect_update_branches(
    if_cond: &str,
    then_bindings: &[ANFBinding],
    else_bindings: &[ANFBinding],
) -> Option<Vec<UpdateBranch>> {
    let then_update = extract_branch_update(then_bindings)?;

    let mut branches = vec![UpdateBranch {
        cond_setup_bindings: Vec::new(),
        cond_ref: Some(if_cond.to_string()),
        prop_name: then_update.0,
        value_bindings: then_update.1,
        value_ref: then_update.2,
    }];

    if else_bindings.is_empty() {
        return None;
    }

    // Check if else is another if (else-if chain)
    let last_else = &else_bindings[else_bindings.len() - 1];
    if let ANFValue::If { cond, then, else_branch, results } = &last_else.value {
        let cond_setup = &else_bindings[..else_bindings.len() - 1];
        if !all_bindings_side_effect_free(cond_setup) {
            return None;
        }

        let inner_results = results.clone();
        let mut inner_branches = collect_update_branches(
            cond,
            strip_declared_results(then, &inner_results),
            strip_declared_results(else_branch, &inner_results),
        )?;

        // Prepend condition setup to first inner branch
        let mut new_setup = cond_setup.to_vec();
        new_setup.extend(inner_branches[0].cond_setup_bindings.drain(..));
        inner_branches[0].cond_setup_bindings = new_setup;

        branches.extend(inner_branches);
        return Some(branches);
    }

    // Otherwise, else branch should end with update_prop (final else)
    if let Some(else_update) = extract_branch_update(else_bindings) {
        branches.push(UpdateBranch {
            cond_setup_bindings: Vec::new(),
            cond_ref: None,
            prop_name: else_update.0,
            value_bindings: else_update.1,
            value_ref: else_update.2,
        });
        return Some(branches);
    }

    // Handle unreachable else: assert(false)
    if is_assert_false_else(else_bindings) {
        return Some(branches);
    }

    None
}

/// Remap temp references in an ANF value according to a name mapping.
fn remap_value_refs(value: &ANFValue, map: &HashMap<String, String>) -> ANFValue {
    let r = |s: &str| -> String { map.get(s).cloned().unwrap_or_else(|| s.to_string()) };
    match value {
        // raw_script carries an opaque byte span with no SSA operand refs —
        // nothing to remap.
        ANFValue::LoadParam { .. }
        | ANFValue::LoadProp { .. }
        | ANFValue::GetStateScript {}
        | ANFValue::RawScript { .. } => value.clone(),
        ANFValue::LoadConst { value: v } => {
            if let Some(s) = v.as_str() {
                if s.starts_with("@ref:") {
                    let target = &s[5..];
                    if let Some(remapped) = map.get(target) {
                        return ANFValue::LoadConst {
                            value: serde_json::Value::String(format!("@ref:{}", remapped)),
                        };
                    }
                }
            }
            value.clone()
        }
        ANFValue::BinOp { op, left, right, result_type } => ANFValue::BinOp {
            op: op.clone(),
            left: r(left),
            right: r(right),
            result_type: result_type.clone(),
        },
        ANFValue::UnaryOp { op, operand, result_type } => ANFValue::UnaryOp {
            op: op.clone(),
            operand: r(operand),
            result_type: result_type.clone(),
        },
        ANFValue::Call { func, args } => ANFValue::Call {
            func: func.clone(),
            args: args.iter().map(|a| r(a)).collect(),
        },
        ANFValue::MethodCall { object, method, args } => ANFValue::MethodCall {
            object: r(object),
            method: method.clone(),
            args: args.iter().map(|a| r(a)).collect(),
        },
        ANFValue::Assert { value: v, is_auto_injected_state_check } => ANFValue::Assert { value: r(v), is_auto_injected_state_check: *is_auto_injected_state_check },
        ANFValue::UpdateProp { name, value: v } => ANFValue::UpdateProp {
            name: name.clone(),
            value: r(v),
        },
        ANFValue::CheckPreimage { preimage, sighash_flag } => ANFValue::CheckPreimage {
            preimage: r(preimage),
            sighash_flag: *sighash_flag,
        },
        ANFValue::DeserializeState { preimage } => ANFValue::DeserializeState {
            preimage: r(preimage),
        },
        ANFValue::AddOutput { satoshis, state_values, preimage } => ANFValue::AddOutput {
            satoshis: r(satoshis),
            state_values: state_values.iter().map(|a| r(a)).collect(),
            preimage: r(preimage),
        },
        ANFValue::AddRawOutput { satoshis, script_bytes } => ANFValue::AddRawOutput {
            satoshis: r(satoshis),
            script_bytes: r(script_bytes),
        },
        ANFValue::AddDataOutput { satoshis, script_bytes } => ANFValue::AddDataOutput {
            satoshis: r(satoshis),
            script_bytes: r(script_bytes),
        },
        ANFValue::ArrayLiteral { elements } => ANFValue::ArrayLiteral {
            elements: elements.iter().map(|e| r(e)).collect(),
        },
        ANFValue::If { cond, then, else_branch, results } => ANFValue::If {
            cond: r(cond),
            then: then.clone(),
            else_branch: else_branch.clone(),
            results: results.clone(),
        },
        ANFValue::Loop { count, body, iter_var, start, step } => ANFValue::Loop {
            count: *count,
            body: body.clone(),
            iter_var: iter_var.clone(),
            start: start.clone(),
            step: *step,
        },
    }
}

/// Transform if-bindings whose branches all end with update_prop into
/// flat conditional assignments. Mirrors TS liftBranchUpdateProps.
fn lift_branch_update_props(bindings: Vec<ANFBinding>) -> Vec<ANFBinding> {
    let mut next_idx = (max_temp_index(&bindings) + 1) as usize;
    let mut fresh = || -> String {
        let name = format!("t{}", next_idx);
        next_idx += 1;
        name
    };

    let mut result: Vec<ANFBinding> = Vec::new();

    for binding in &bindings {
        let if_val = match &binding.value {
            ANFValue::If { cond, then, else_branch, results } => {
                Some((cond, then, else_branch, results))
            }
            _ => None,
        };

        if if_val.is_none() {
            result.push(binding.clone());
            continue;
        }

        let (cond, then_bindings, else_bindings, own_results) = if_val.unwrap();

        let own_results = own_results.clone();
        let branches = collect_update_branches(
            cond,
            strip_declared_results(then_bindings, &own_results),
            strip_declared_results(else_bindings, &own_results),
        );

        if branches.is_none() || branches.as_ref().map_or(true, |b| b.len() < 2) {
            result.push(binding.clone());
            continue;
        }

        let branches = branches.unwrap();

        // --- Transform: flatten into conditional assignments ---

        // 1. Hoist condition setup bindings with fresh names
        let mut name_map: HashMap<String, String> = HashMap::new();
        let mut cond_refs: Vec<Option<String>> = Vec::new();

        for branch in &branches {
            for csb in &branch.cond_setup_bindings {
                let new_name = fresh();
                name_map.insert(csb.name.clone(), new_name.clone());
                result.push(ANFBinding {
                    name: new_name,
                    value: remap_value_refs(&csb.value, &name_map),
                    source_loc: None,
                });
            }
            cond_refs.push(
                branch.cond_ref.as_ref().map(|cr| {
                    name_map.get(cr).cloned().unwrap_or_else(|| cr.clone())
                }),
            );
        }

        // 2. Compute effective condition for each branch
        let mut effective_conds: Vec<String> = Vec::new();
        let mut negated_conds: Vec<String> = Vec::new();

        for i in 0..branches.len() {
            if i == 0 {
                effective_conds.push(cond_refs[0].clone().unwrap());
                continue;
            }

            // Negate any prior conditions not yet negated
            for j in negated_conds.len()..i {
                if cond_refs[j].is_none() {
                    continue;
                }
                let neg_name = fresh();
                result.push(ANFBinding {
                    name: neg_name.clone(),
                    value: ANFValue::UnaryOp {
                        op: "!".to_string(),
                        operand: cond_refs[j].clone().unwrap(),
                        result_type: None,
                    },
                    source_loc: None,
                });
                negated_conds.push(neg_name);
            }

            // AND all negated conditions together
            let mut and_ref = negated_conds[0].clone();
            for j in 1..std::cmp::min(i, negated_conds.len()) {
                let and_name = fresh();
                result.push(ANFBinding {
                    name: and_name.clone(),
                    value: ANFValue::BinOp {
                        op: "&&".to_string(),
                        left: and_ref,
                        right: negated_conds[j].clone(),
                        result_type: None,
                    },
                    source_loc: None,
                });
                and_ref = and_name;
            }

            if cond_refs[i].is_some() {
                // Middle branch: AND with own condition
                let final_name = fresh();
                result.push(ANFBinding {
                    name: final_name.clone(),
                    value: ANFValue::BinOp {
                        op: "&&".to_string(),
                        left: and_ref,
                        right: cond_refs[i].clone().unwrap(),
                        result_type: None,
                    },
                    source_loc: None,
                });
                effective_conds.push(final_name);
            } else {
                // Final else: just the AND of negations
                effective_conds.push(and_ref);
            }
        }

        // 2b. C20 — preserve a dropped terminal `assert(false)` else.
        //
        // `collect_update_branches` transforms a dispatch chain whose branches
        // each end in a single `update_prop` into this flat conditional-assignment
        // form. When the chain's terminal else is `assert(false)` it returns the
        // branches WITHOUT a catch-all final branch (every branch keeps a non-null
        // cond_ref), dropping the abort. But that assert(false) is the ONLY thing
        // rejecting a selector value that matches no branch: without it, an
        // unmatched selector leaves every property at its old value — a spendable
        // NO-OP state continuation instead of a failed script (a funds-safety bug).
        //
        // A real final else (`else { prop = ... }`) instead yields a catch-all
        // branch with cond_ref === None, and needs no guard because every selector
        // value maps to some branch. So the presence of a None-cond_ref terminal
        // branch exactly distinguishes the two cases.
        //
        // Re-introduce the abort as `assert(cond0 || cond1 || ... || cond_{N-1})`:
        // if no branch condition held, the OR is false and the script aborts —
        // byte-identical to the original `assert(false)` semantics for the
        // unmatched position, and a no-op (`assert(true)`) whenever a branch runs.
        let has_catch_all_else = branches[branches.len() - 1].cond_ref.is_none();
        if !has_catch_all_else {
            // Every branch here has a non-null cond_ref (only a catch-all final
            // else is None, and there is none), so the OR fully covers selectors.
            let mut or_ref = cond_refs[0].clone().unwrap();
            for i in 1..cond_refs.len() {
                let or_name = fresh();
                result.push(ANFBinding {
                    name: or_name.clone(),
                    value: ANFValue::BinOp {
                        op: "||".to_string(),
                        left: or_ref,
                        right: cond_refs[i].clone().unwrap(),
                        result_type: None,
                    },
                    source_loc: None,
                });
                or_ref = or_name;
            }
            result.push(ANFBinding {
                name: fresh(),
                value: ANFValue::Assert {
                    value: or_ref,
                    is_auto_injected_state_check: false,
                },
                source_loc: None,
            });
        }

        // 3. For each branch, emit: load_old, conditional if-expression, update_prop
        for (i, branch) in branches.iter().enumerate() {
            // Load old property value
            let old_prop_ref = fresh();
            result.push(ANFBinding {
                name: old_prop_ref.clone(),
                value: ANFValue::LoadProp {
                    name: branch.prop_name.clone(),
                },
                source_loc: None,
            });

            // Remap value bindings for the then-branch
            let mut branch_map = name_map.clone();
            let mut then_bindings: Vec<ANFBinding> = Vec::new();
            for vb in &branch.value_bindings {
                let new_name = fresh();
                branch_map.insert(vb.name.clone(), new_name.clone());
                then_bindings.push(ANFBinding {
                    name: new_name,
                    value: remap_value_refs(&vb.value, &branch_map),
                    source_loc: None,
                });
            }

            // Else branch: keep old property value
            let keep_name = fresh();
            let else_bindings = vec![ANFBinding {
                name: keep_name,
                value: ANFValue::LoadConst {
                    value: serde_json::Value::String(format!("@ref:{}", old_prop_ref)),
                },
                source_loc: None,
            }];

            // Emit conditional if-expression
            let cond_if_ref = fresh();
            result.push(ANFBinding {
                name: cond_if_ref.clone(),
                value: ANFValue::If {
                    cond: effective_conds[i].clone(),
                    then: then_bindings,
                    else_branch: else_bindings,
                    results: Vec::new(),
                },
                source_loc: None,
            });

            // Emit update_prop
            result.push(ANFBinding {
                name: fresh(),
                value: ANFValue::UpdateProp {
                    name: branch.prop_name.clone(),
                    value: cond_if_ref,
                },
                source_loc: None,
            });
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::parser::parse_source;
    use crate::frontend::typecheck::typecheck;
    use crate::frontend::validator::validate;

    /// Helper: parse → validate → typecheck → return ContractNode.
    fn must_lower_to_anf(source: &str) -> ContractNode {
        let result = parse_source(source, Some("test.runar.ts"));
        assert!(
            result.errors.is_empty(),
            "parse errors: {:?}",
            result.errors
        );
        let contract = result.contract.expect("expected a contract from parse");

        let val_result = validate(&contract);
        assert!(
            val_result.errors.is_empty(),
            "validation errors: {:?}",
            val_result.errors
        );

        let tc_result = typecheck(&contract);
        assert!(
            tc_result.errors.is_empty(),
            "type check errors: {:?}",
            tc_result.errors
        );

        contract
    }

    // -----------------------------------------------------------------------
    // test_p2pkh_has_properties
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_has_properties() {
        let source = r#"
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey): void {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        assert_eq!(program.contract_name, "P2PKH");

        assert_eq!(
            program.properties.len(),
            1,
            "expected 1 property, got {}",
            program.properties.len()
        );
        let prop = &program.properties[0];
        assert_eq!(
            prop.name, "pubKeyHash",
            "expected property name 'pubKeyHash', got '{}'",
            prop.name
        );
        assert_eq!(
            prop.prop_type, "Addr",
            "expected property type 'Addr', got '{}'",
            prop.prop_type
        );
        assert!(prop.readonly, "expected property to be readonly");
    }

    // -----------------------------------------------------------------------
    // test_p2pkh_unlock_has_bindings
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_unlock_has_bindings() {
        let source = r#"
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey): void {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        let unlock = program
            .methods
            .iter()
            .find(|m| m.name == "unlock")
            .expect("could not find 'unlock' method in ANF output");

        assert!(unlock.is_public, "expected unlock method to be public");

        assert_eq!(
            unlock.params.len(),
            2,
            "expected 2 params (sig, pubKey), got {}",
            unlock.params.len()
        );
        assert_eq!(unlock.params[0].name, "sig");
        assert_eq!(unlock.params[0].param_type, "Sig");
        assert_eq!(unlock.params[1].name, "pubKey");
        assert_eq!(unlock.params[1].param_type, "PubKey");

        // Count binding kinds — must have at least: 2 load_param, 2 call, 1
        // load_prop, 1 bin_op, 2 assert.
        let mut load_param_count = 0usize;
        let mut call_count = 0usize;
        let mut load_prop_count = 0usize;
        let mut bin_op_count = 0usize;
        let mut assert_count = 0usize;

        for b in &unlock.body {
            match &b.value {
                ANFValue::LoadParam { .. } => load_param_count += 1,
                ANFValue::LoadProp { .. } => load_prop_count += 1,
                ANFValue::Call { .. } => call_count += 1,
                ANFValue::BinOp { .. } => bin_op_count += 1,
                ANFValue::Assert { .. } => assert_count += 1,
                _ => {}
            }
        }

        assert!(
            load_param_count >= 2,
            "expected at least 2 load_param bindings, got {}",
            load_param_count
        );
        assert!(
            call_count >= 2,
            "expected at least 2 call bindings (hash160, checkSig), got {}",
            call_count
        );
        assert!(
            load_prop_count >= 1,
            "expected at least 1 load_prop binding (pubKeyHash), got {}",
            load_prop_count
        );
        assert!(
            bin_op_count >= 1,
            "expected at least 1 bin_op binding (===), got {}",
            bin_op_count
        );
        assert!(
            assert_count >= 2,
            "expected at least 2 assert bindings, got {}",
            assert_count
        );
    }

    // -----------------------------------------------------------------------
    // test_p2pkh_binding_details
    // -----------------------------------------------------------------------

    #[test]
    fn test_p2pkh_binding_details() {
        let source = r#"
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey): void {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        let unlock = program
            .methods
            .iter()
            .find(|m| m.name == "unlock")
            .expect("could not find 'unlock' method");

        // Verify call to hash160 with 1 argument
        let hash160_binding = unlock.body.iter().find(|b| {
            matches!(&b.value, ANFValue::Call { func, .. } if func == "hash160")
        });
        assert!(
            hash160_binding.is_some(),
            "expected a call to hash160 in unlock method bindings"
        );
        if let Some(b) = hash160_binding {
            if let ANFValue::Call { args, .. } = &b.value {
                assert_eq!(
                    args.len(),
                    1,
                    "hash160 should have 1 arg, got {}",
                    args.len()
                );
            }
        }

        // Verify call to checkSig with 2 arguments
        let checksig_binding = unlock.body.iter().find(|b| {
            matches!(&b.value, ANFValue::Call { func, .. } if func == "checkSig")
        });
        assert!(
            checksig_binding.is_some(),
            "expected a call to checkSig in unlock method bindings"
        );
        if let Some(b) = checksig_binding {
            if let ANFValue::Call { args, .. } = &b.value {
                assert_eq!(
                    args.len(),
                    2,
                    "checkSig should have 2 args, got {}",
                    args.len()
                );
            }
        }

        // Verify bin_op === has result_type "bytes" (byte-typed equality)
        let eq_binding = unlock.body.iter().find(|b| {
            matches!(&b.value, ANFValue::BinOp { op, .. } if op == "===")
        });
        assert!(
            eq_binding.is_some(),
            "expected a bin_op === in unlock method bindings"
        );
        if let Some(b) = eq_binding {
            if let ANFValue::BinOp { result_type, .. } = &b.value {
                assert_eq!(
                    result_type.as_deref(),
                    Some("bytes"),
                    "expected bin_op === to have result_type 'bytes' (byte-typed equality), got {:?}",
                    result_type
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // test_constructor_included
    // -----------------------------------------------------------------------

    #[test]
    fn test_constructor_included() {
        let source = r#"
import { SmartContract, assert } from 'runar-lang';

class Simple extends SmartContract {
  readonly x: bigint;

  constructor(x: bigint) {
    super(x);
    this.x = x;
  }

  public check(val: bigint): void {
    assert(val === this.x);
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        assert!(
            program.methods.len() >= 2,
            "expected at least 2 methods (constructor + check), got {}",
            program.methods.len()
        );

        let ctor = &program.methods[0];
        assert_eq!(
            ctor.name, "constructor",
            "expected first method to be 'constructor', got '{}'",
            ctor.name
        );
        assert!(!ctor.is_public, "constructor should not be public");
    }

    // -----------------------------------------------------------------------
    // test_arithmetic_bindings
    // -----------------------------------------------------------------------

    #[test]
    fn test_arithmetic_bindings() {
        let source = r#"
import { SmartContract, assert } from 'runar-lang';

class ArithTest extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(a: bigint, b: bigint): void {
    assert(a + b === this.target);
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        let verify = program
            .methods
            .iter()
            .find(|m| m.name == "verify")
            .expect("could not find 'verify' method");

        // Should have a bin_op + for a + b
        let add_binding = verify.body.iter().find(|b| {
            matches!(&b.value, ANFValue::BinOp { op, .. } if op == "+")
        });
        assert!(
            add_binding.is_some(),
            "expected bin_op + in verify method for 'a + b'"
        );

        // Should have a bin_op === for equality check
        let eq_binding = verify.body.iter().find(|b| {
            matches!(&b.value, ANFValue::BinOp { op, .. } if op == "===")
        });
        assert!(
            eq_binding.is_some(),
            "expected bin_op === in verify method"
        );
    }

    // -----------------------------------------------------------------------
    // test_if_else_lowering
    // Mirrors Python test_anf_lower_if_else
    // -----------------------------------------------------------------------

    #[test]
    fn test_if_else_lowering() {
        let source = r#"
import { SmartContract, assert } from 'runar-lang';

class IfElse extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public check(value: bigint, mode: boolean): void {
    let result: bigint = 0n;
    if (mode) {
      result = value + this.limit;
    } else {
      result = value - this.limit;
    }
    assert(result > 0n);
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        let check = program
            .methods
            .iter()
            .find(|m| m.name == "check")
            .expect("could not find 'check' method");

        // The if/else construct should produce an ANFValue::If binding
        let has_if_binding = check
            .body
            .iter()
            .any(|b| matches!(b.value, ANFValue::If { .. }));

        assert!(
            has_if_binding,
            "expected an 'if' binding in the ANF output for the if/else construct, got: {:?}",
            check.body.iter().map(|b| format!("{:?}", b.value)).collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // test_stateful_has_implicit_params
    // Mirrors Python test_typecheck_valid_stateful (checks implicit params in ANF)
    // -----------------------------------------------------------------------

    #[test]
    fn test_stateful_has_implicit_params() {
        let source = r#"
import { StatefulSmartContract, assert } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment(amount: bigint): void {
    this.count = this.count + amount;
    assert(this.count > 0n);
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        let increment = program
            .methods
            .iter()
            .find(|m| m.name == "increment")
            .expect("could not find 'increment' method");

        // A StatefulSmartContract public method should have implicit params injected:
        // txPreimage, _changePKH, _changeAmount
        let param_names: Vec<&str> = increment.params.iter().map(|p| p.name.as_str()).collect();

        assert!(
            param_names.contains(&"txPreimage"),
            "stateful method should have 'txPreimage' as an implicit param, got: {:?}",
            param_names
        );
        assert!(
            param_names.contains(&"_changePKH"),
            "stateful method should have '_changePKH' as an implicit param, got: {:?}",
            param_names
        );
        assert!(
            param_names.contains(&"_changeAmount"),
            "stateful method should have '_changeAmount' as an implicit param, got: {:?}",
            param_names
        );
    }

    // -----------------------------------------------------------------------
    // Ternary expression lowers to an ANFValue::If node (T-5)
    // Mirrors the Java peer test (StackLowerTest#ternaryLowersToIfOpStructural)
    // and the Go peer (anf_lower_test.go TestANFLower_Ternary). Localized
    // regression detection — otherwise covered only by the cross-tier golden
    // harness.
    // -----------------------------------------------------------------------

    #[test]
    fn test_ternary_lowers_to_if() {
        let source = r#"
import { SmartContract, assert } from 'runar-lang';

class TernaryDemo extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public check(flag: boolean): void {
    const result: bigint = flag ? this.limit + 1n : this.limit - 1n;
    assert(result > 0n);
  }
}
"#;
        let contract = must_lower_to_anf(source);
        let program = lower_to_anf(&contract);

        let check = program
            .methods
            .iter()
            .find(|m| m.name == "check")
            .expect("could not find 'check' method");

        let if_binding = check
            .body
            .iter()
            .find(|b| matches!(b.value, ANFValue::If { .. }));

        let if_value = if_binding
            .map(|b| &b.value)
            .expect("expected ternary to lower to an ANFValue::If binding");

        if let ANFValue::If { then, else_branch, .. } = if_value {
            assert!(!then.is_empty(), "ternary `then` branch should not be empty");
            assert!(
                !else_branch.is_empty(),
                "ternary `else` branch should not be empty"
            );
        }
    }

    // -----------------------------------------------------------------------
    // #121: extract_loop_shape — non-zero start and countdown support
    // -----------------------------------------------------------------------

    /// Parse only (no validate) so the anf-lower loop-shape path is exercised.
    fn parse_only(source: &str) -> ContractNode {
        let result = parse_source(source, Some("test.runar.ts"));
        assert!(result.errors.is_empty(), "parse errors: {:?}", result.errors);
        result.contract.expect("expected a contract from parse")
    }

    /// Find the first `loop` node anywhere in a lowered program.
    fn find_loop(anf: &ANFProgram) -> (usize, serde_json::Value, i64) {
        fn walk(bindings: &[ANFBinding]) -> Option<(usize, serde_json::Value, i64)> {
            for b in bindings {
                match &b.value {
                    ANFValue::Loop { count, start, step, .. } => {
                        return Some((*count, start.clone(), *step));
                    }
                    ANFValue::If { then, else_branch, .. } => {
                        if let Some(r) = walk(then).or_else(|| walk(else_branch)) {
                            return Some(r);
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        for m in &anf.methods {
            if let Some(r) = walk(&m.body) {
                return r;
            }
        }
        panic!("no loop node found");
    }

    #[test]
    fn test_extract_loop_shape_non_zero_start() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class NonZeroStart extends SmartContract {
    readonly n: bigint;

    constructor(n: bigint) {
        super(n);
        this.n = n;
    }

    public run(v: bigint) {
        let sum = 0n;
        for (let i = 1n; i < 3n; i++) {
            sum = sum + i;
        }
        assert(sum === v);
    }
}
"#;
        let contract = parse_only(source);
        let anf = lower_to_anf(&contract);
        let (count, start, step) = find_loop(&anf);
        assert_eq!(count, 2);
        assert_eq!(start, serde_json::json!(1));
        assert_eq!(step, 1);
    }

    #[test]
    fn test_extract_loop_shape_countdown() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class Countdown extends SmartContract {
    readonly n: bigint;

    constructor(n: bigint) {
        super(n);
        this.n = n;
    }

    public run(v: bigint) {
        let sum = 0n;
        for (let i = 3n; i > 0n; i--) {
            sum = sum + i;
        }
        assert(sum === v);
    }
}
"#;
        let contract = parse_only(source);
        let anf = lower_to_anf(&contract);
        let (count, start, step) = find_loop(&anf);
        assert_eq!(count, 3);
        assert_eq!(start, serde_json::json!(3));
        assert_eq!(step, -1);
    }

    // -----------------------------------------------------------------------
    // #130: a method param whose name shadows a property resolves to the param
    // for bare identifiers, while explicit `this.x` still resolves to the
    // property.
    // -----------------------------------------------------------------------

    /// Count `load_param` / `load_prop` bindings referencing `name` anywhere in
    /// a method body (recursing into if/loop bodies).
    fn count_loads(bindings: &[ANFBinding], kind_is_param: bool, name: &str) -> usize {
        let mut n = 0;
        for b in bindings {
            match &b.value {
                ANFValue::LoadParam { name: pn } if kind_is_param && pn == name => n += 1,
                ANFValue::LoadProp { name: pn } if !kind_is_param && pn == name => n += 1,
                ANFValue::If { then, else_branch, .. } => {
                    n += count_loads(then, kind_is_param, name);
                    n += count_loads(else_branch, kind_is_param, name);
                }
                ANFValue::Loop { body, .. } => {
                    n += count_loads(body, kind_is_param, name);
                }
                _ => {}
            }
        }
        n
    }

    #[test]
    fn test_param_shadowing_property_resolves_both_directions() {
        let source = r#"
import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
    readonly x: bigint;
    constructor(x: bigint) { super(x); this.x = x; }
    public m(x: bigint) {
        assert(x === this.x);
    }
}
"#;
        let contract = parse_only(source);
        let anf = lower_to_anf(&contract);
        let m = anf.methods.iter().find(|m| m.name == "m").expect("method m");
        // bare `x` -> load_param (the witness value), not the property.
        assert_eq!(count_loads(&m.body, true, "x"), 1, "expected one load_param x");
        // explicit `this.x` -> load_prop (the stored property).
        assert_eq!(count_loads(&m.body, false, "x"), 1, "expected one load_prop x");
    }
}
