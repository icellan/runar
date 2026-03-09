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

use std::collections::{HashMap, HashSet};

use super::ast::*;
use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFProperty, ANFValue};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Lower a type-checked Rúnar AST to ANF IR.
pub fn lower_to_anf(contract: &ContractNode) -> ANFProgram {
    let properties = lower_properties(contract);
    let methods = lower_methods(contract);

    ANFProgram {
        contract_name: contract.name.clone(),
        properties,
        methods,
    }
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

fn lower_properties(contract: &ContractNode) -> Vec<ANFProperty> {
    contract
        .properties
        .iter()
        .map(|prop| ANFProperty {
            name: prop.name.clone(),
            prop_type: type_node_to_string(&prop.prop_type),
            readonly: prop.readonly,
            initial_value: prop.initializer.as_ref().and_then(extract_literal_value),
        })
        .collect()
}

fn extract_literal_value(expr: &Expression) -> Option<serde_json::Value> {
    match expr {
        Expression::BigIntLiteral { value } => Some(serde_json::Value::Number(
            serde_json::Number::from(*value),
        )),
        Expression::BoolLiteral { value } => Some(serde_json::Value::Bool(*value)),
        Expression::ByteStringLiteral { value } => {
            Some(serde_json::Value::String(value.clone()))
        }
        Expression::UnaryExpr {
            op: UnaryOp::Neg,
            operand,
        } => {
            if let Expression::BigIntLiteral { value } = operand.as_ref() {
                Some(serde_json::Value::Number(serde_json::Number::from(-*value)))
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

    // Lower constructor (the TS reference includes the constructor in output)
    let mut ctor_ctx = LoweringContext::new(contract);
    lower_statements(&contract.constructor.body, &mut ctor_ctx);
    result.push(ANFMethod {
        name: "constructor".to_string(),
        params: lower_params(&contract.constructor.params),
        body: ctor_ctx.bindings,
        is_public: false,
    });

    // Lower each method (including private methods as separate entries)
    for method in &contract.methods {
        let mut method_ctx = LoweringContext::new(contract);

        if contract.parent_class == "InductiveSmartContract"
            && method.visibility == Visibility::Public
        {
            // ---------------------------------------------------------------
            // InductiveSmartContract public method lowering
            // ---------------------------------------------------------------

            // Register implicit parameters: parentTx + txPreimage
            method_ctx.add_param("parentTx");
            method_ctx.add_param("txPreimage");

            // 1. Inject checkPreimage(txPreimage) at the start
            let preimage_ref = method_ctx.emit(ANFValue::LoadParam {
                name: "txPreimage".to_string(),
            });
            let check_result = method_ctx.emit(ANFValue::CheckPreimage {
                preimage: preimage_ref,
            });
            method_ctx.emit(ANFValue::Assert {
                value: check_result,
            });

            // 2. Verify parent tx authenticity:
            //    assert(hash256(parentTx) === left(extractOutpoint(txPreimage), 32))
            let parent_tx_ref = method_ctx.emit(ANFValue::LoadParam {
                name: "parentTx".to_string(),
            });
            let parent_tx_hash = method_ctx.emit(ANFValue::Call {
                func: "hash256".to_string(),
                args: vec![parent_tx_ref],
            });
            let preimage_ref2 = method_ctx.emit(ANFValue::LoadParam {
                name: "txPreimage".to_string(),
            });
            let outpoint_ref = method_ctx.emit(ANFValue::Call {
                func: "extractOutpoint".to_string(),
                args: vec![preimage_ref2],
            });
            let thirty_two = method_ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from(32i64)),
            });
            let parent_txid_from_preimage = method_ctx.emit(ANFValue::Call {
                func: "left".to_string(),
                args: vec![outpoint_ref, thirty_two],
            });
            let parent_hash_eq = method_ctx.emit(ANFValue::BinOp {
                op: "===".to_string(),
                left: parent_tx_hash,
                right: parent_txid_from_preimage,
                result_type: Some("bytes".to_string()),
            });
            method_ctx.emit(ANFValue::Assert {
                value: parent_hash_eq,
            });

            // 3. Genesis detection: if (_genesisOutpoint === 0x00..00_36)
            let genesis_ref = method_ctx.emit(ANFValue::LoadProp {
                name: "_genesisOutpoint".to_string(),
            });
            // 36 bytes = 72 hex chars of zeros
            let zero_sentinel = method_ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::String("0".repeat(72)),
            });
            let is_genesis = method_ctx.emit(ANFValue::BinOp {
                op: "===".to_string(),
                left: genesis_ref,
                right: zero_sentinel,
                result_type: Some("bytes".to_string()),
            });

            // Genesis branch: set _genesisOutpoint = extractOutpoint(txPreimage)
            let mut genesis_ctx = method_ctx.sub_context();
            let gp_ref = genesis_ctx.emit(ANFValue::LoadParam {
                name: "txPreimage".to_string(),
            });
            let current_outpoint = genesis_ctx.emit(ANFValue::Call {
                func: "extractOutpoint".to_string(),
                args: vec![gp_ref],
            });
            genesis_ctx.emit(ANFValue::UpdateProp {
                name: "_genesisOutpoint".to_string(),
                value: current_outpoint,
            });
            method_ctx.sync_counter(&genesis_ctx);

            // Non-genesis branch: verify chain consistency
            let mut non_genesis_ctx = method_ctx.sub_context();
            // Extract parent output script via extract_parent_output
            let ptx_ref = non_genesis_ctx.emit(ANFValue::LoadParam {
                name: "parentTx".to_string(),
            });
            // Derive output index dynamically from the current transaction's outpoint.
            // The outpoint is 36 bytes: 32-byte txid + 4-byte vout (little-endian).
            // We extract the last 4 bytes (vout) and convert to a number via OP_BIN2NUM.
            let preimage_for_idx = non_genesis_ctx.emit(ANFValue::LoadParam {
                name: "txPreimage".to_string(),
            });
            let outpoint_for_idx = non_genesis_ctx.emit(ANFValue::Call {
                func: "extractOutpoint".to_string(),
                args: vec![preimage_for_idx],
            });
            let four = non_genesis_ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from(4i64)),
            });
            let output_idx_bytes = non_genesis_ctx.emit(ANFValue::Call {
                func: "right".to_string(),
                args: vec![outpoint_for_idx, four],
            });
            let output_idx = non_genesis_ctx.emit(ANFValue::UnaryOp {
                op: "unpack".to_string(),
                operand: output_idx_bytes,
            });
            let parent_script = non_genesis_ctx.emit(ANFValue::ExtractParentOutput {
                raw_tx: ptx_ref,
                output_index: output_idx,
            });

            // Extract internal fields from the END of parent script
            // Internal fields are 3 fields * 36 bytes each = 108 bytes of data
            // Each push-data field in Script is: 0x24 (push 36 bytes) + 36 bytes = 37 bytes
            // Total: 3 * 37 = 111 bytes from the end of the script
            let parent_script_len = non_genesis_ctx.emit(ANFValue::Call {
                func: "len".to_string(),
                args: vec![parent_script.clone()],
            });
            let one_eleven = non_genesis_ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from(111i64)),
            });
            let _prefix_len = non_genesis_ctx.emit(ANFValue::BinOp {
                op: "-".to_string(),
                left: parent_script_len,
                right: one_eleven.clone(),
                result_type: None,
            });
            // Use right(parentScript, 111) to get the last 111 bytes
            let internal_fields_with_prefixes = non_genesis_ctx.emit(ANFValue::Call {
                func: "right".to_string(),
                args: vec![parent_script, one_eleven],
            });

            // Extract each 37-byte field (1 push opcode + 36 data bytes)
            let thirty_seven_c = non_genesis_ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from(37i64)),
            });
            let thirty_six_c = non_genesis_ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from(36i64)),
            });
            let _one_c = non_genesis_ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from(1i64)),
            });

            // parentGenesis: bytes [1..37) (skip push opcode at byte 0)
            let parent_genesis_raw = non_genesis_ctx.emit(ANFValue::Call {
                func: "left".to_string(),
                args: vec![internal_fields_with_prefixes.clone(), thirty_seven_c.clone()],
            });
            let parent_genesis = non_genesis_ctx.emit(ANFValue::Call {
                func: "right".to_string(),
                args: vec![parent_genesis_raw, thirty_six_c.clone()],
            });

            // parentParentOutpoint: bytes [38..74) (skip push opcode at byte 37)
            let seventy_four_c = non_genesis_ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Number(serde_json::Number::from(74i64)),
            });
            let parent_parent_outpoint_raw = non_genesis_ctx.emit(ANFValue::Call {
                func: "left".to_string(),
                args: vec![internal_fields_with_prefixes, seventy_four_c],
            });
            let parent_parent_outpoint_with_prefix = non_genesis_ctx.emit(ANFValue::Call {
                func: "right".to_string(),
                args: vec![parent_parent_outpoint_raw, thirty_seven_c],
            });
            let parent_parent_outpoint = non_genesis_ctx.emit(ANFValue::Call {
                func: "right".to_string(),
                args: vec![parent_parent_outpoint_with_prefix, thirty_six_c],
            });

            // Assert: parentGenesis === _genesisOutpoint (same lineage)
            let my_genesis = non_genesis_ctx.emit(ANFValue::LoadProp {
                name: "_genesisOutpoint".to_string(),
            });
            let genesis_eq = non_genesis_ctx.emit(ANFValue::BinOp {
                op: "===".to_string(),
                left: parent_genesis,
                right: my_genesis,
                result_type: Some("bytes".to_string()),
            });
            non_genesis_ctx.emit(ANFValue::Assert {
                value: genesis_eq,
            });

            // Assert: parentParentOutpoint === _grandparentOutpoint (chain links match)
            let my_grandparent = non_genesis_ctx.emit(ANFValue::LoadProp {
                name: "_grandparentOutpoint".to_string(),
            });
            let chain_eq = non_genesis_ctx.emit(ANFValue::BinOp {
                op: "===".to_string(),
                left: parent_parent_outpoint,
                right: my_grandparent,
                result_type: Some("bytes".to_string()),
            });
            non_genesis_ctx.emit(ANFValue::Assert {
                value: chain_eq,
            });
            method_ctx.sync_counter(&non_genesis_ctx);

            // Emit the if/else
            method_ctx.emit(ANFValue::If {
                cond: is_genesis,
                then: genesis_ctx.bindings,
                else_branch: non_genesis_ctx.bindings,
            });

            // 4. Inject internal field updates BEFORE the developer body, so that
            //    addOutput calls in the developer's code pick up the updated values
            //    via auto-appended load_prop references.
            //    _grandparentOutpoint = _parentOutpoint
            let old_parent = method_ctx.emit(ANFValue::LoadProp {
                name: "_parentOutpoint".to_string(),
            });
            method_ctx.emit(ANFValue::UpdateProp {
                name: "_grandparentOutpoint".to_string(),
                value: old_parent,
            });
            //    _parentOutpoint = extractOutpoint(txPreimage)
            let preimage_ref3 = method_ctx.emit(ANFValue::LoadParam {
                name: "txPreimage".to_string(),
            });
            let current_outpoint2 = method_ctx.emit(ANFValue::Call {
                func: "extractOutpoint".to_string(),
                args: vec![preimage_ref3],
            });
            method_ctx.emit(ANFValue::UpdateProp {
                name: "_parentOutpoint".to_string(),
                value: current_outpoint2,
            });

            // 5. Lower the developer's method body
            lower_statements(&method.body, &mut method_ctx);

            // 6. State continuation (same as StatefulSmartContract)
            let add_output_refs = method_ctx.add_output_refs.clone();
            if !add_output_refs.is_empty() {
                // Multi-output continuation
                let mut accumulated = add_output_refs[0].clone();
                for i in 1..add_output_refs.len() {
                    accumulated = method_ctx.emit(ANFValue::Call {
                        func: "cat".to_string(),
                        args: vec![accumulated, add_output_refs[i].clone()],
                    });
                }
                let hash_ref = method_ctx.emit(ANFValue::Call {
                    func: "hash256".to_string(),
                    args: vec![accumulated],
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
                method_ctx.emit(ANFValue::Assert { value: eq_ref });
            } else {
                // InductiveSmartContract always mutates state (internal fields)
                let state_script_ref = method_ctx.emit(ANFValue::GetStateScript {});
                let hash_ref = method_ctx.emit(ANFValue::Call {
                    func: "hash256".to_string(),
                    args: vec![state_script_ref],
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
                method_ctx.emit(ANFValue::Assert { value: eq_ref });
            }

            // Append implicit params: parentTx + txPreimage
            let mut augmented_params = lower_params(&method.params);
            augmented_params.push(ANFParam {
                name: "parentTx".to_string(),
                param_type: "ByteString".to_string(),
            });
            augmented_params.push(ANFParam {
                name: "txPreimage".to_string(),
                param_type: "SigHashPreimage".to_string(),
            });

            result.push(ANFMethod {
                name: method.name.clone(),
                params: augmented_params,
                body: method_ctx.bindings,
                is_public: true,
            });
        } else if contract.parent_class == "StatefulSmartContract"
            && method.visibility == Visibility::Public
        {
            // Determine if this method verifies hashOutputs (needs change output support).
            // Methods that use addOutput or mutate state need hashOutputs verification.
            // Non-mutating methods (like close/destroy) don't verify outputs.
            let needs_change_output =
                method_mutates_state(method, contract) || method_has_add_output(method);

            // Single-output continuation needs _newAmount to allow changing the UTXO satoshis.
            // Methods with addOutput don't need it (they build outputs explicitly).
            let needs_new_amount =
                method_mutates_state(method, contract) && !method_has_add_output(method);

            // Register implicit parameters
            if needs_change_output {
                method_ctx.add_param("_changePKH");
                method_ctx.add_param("_changeAmount");
            }
            if needs_new_amount {
                method_ctx.add_param("_newAmount");
            }
            method_ctx.add_param("txPreimage");

            // Inject checkPreimage(txPreimage) at the start
            let preimage_ref = method_ctx.emit(ANFValue::LoadParam {
                name: "txPreimage".to_string(),
            });
            let check_result = method_ctx.emit(ANFValue::CheckPreimage {
                preimage: preimage_ref,
            });
            method_ctx.emit(ANFValue::Assert {
                value: check_result,
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

            // Lower the developer's method body
            lower_statements(&method.body, &mut method_ctx);

            // Determine state continuation type
            let add_output_refs = method_ctx.add_output_refs.clone();
            if !add_output_refs.is_empty() || method_mutates_state(method, contract) {
                // Build the P2PKH change output for hashOutputs verification
                let change_pkh_ref = method_ctx.emit(ANFValue::LoadParam {
                    name: "_changePKH".to_string(),
                });
                let change_amount_ref = method_ctx.emit(ANFValue::LoadParam {
                    name: "_changeAmount".to_string(),
                });
                let change_output_ref = method_ctx.emit(ANFValue::Call {
                    func: "buildChangeOutput".to_string(),
                    args: vec![change_pkh_ref, change_amount_ref],
                });

                if !add_output_refs.is_empty() {
                    // Multi-output continuation: concat all outputs + change output, hash
                    let mut accumulated = add_output_refs[0].clone();
                    for i in 1..add_output_refs.len() {
                        accumulated = method_ctx.emit(ANFValue::Call {
                            func: "cat".to_string(),
                            args: vec![accumulated, add_output_refs[i].clone()],
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
                    method_ctx.emit(ANFValue::Assert { value: eq_ref });
                } else {
                    // Single-output continuation: build raw output bytes, concat with change, hash
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
                    let all_outputs = method_ctx.emit(ANFValue::Call {
                        func: "cat".to_string(),
                        args: vec![contract_output_ref, change_output_ref],
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
                    method_ctx.emit(ANFValue::Assert { value: eq_ref });
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

            result.push(ANFMethod {
                name: method.name.clone(),
                params: augmented_params,
                body: method_ctx.bindings,
                is_public: true,
            });
        } else {
            lower_statements(&method.body, &mut method_ctx);
            result.push(ANFMethod {
                name: method.name.clone(),
                params: lower_params(&method.params),
                body: method_ctx.bindings,
                is_public: method.visibility == Visibility::Public,
            });
        }
    }

    result
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

struct LoweringContext<'a> {
    bindings: Vec<ANFBinding>,
    counter: usize,
    contract: &'a ContractNode,
    param_names: HashSet<String>,
    local_names: HashSet<String>,
    add_output_refs: Vec<String>,
    /// Maps local variable names to their current ANF binding name.
    /// Updated after if-statements that reassign locals in both branches.
    local_aliases: HashMap<String, String>,
    /// Tracks local variables known to be byte-typed.
    local_byte_vars: HashSet<String>,
}

impl<'a> LoweringContext<'a> {
    fn new(contract: &'a ContractNode) -> Self {
        LoweringContext {
            bindings: Vec::new(),
            counter: 0,
            contract,
            param_names: HashSet::new(),
            local_names: HashSet::new(),
            add_output_refs: Vec::new(),
            local_aliases: HashMap::new(),
            local_byte_vars: HashSet::new(),
        }
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
        });
        name
    }

    /// Emit a binding with a specific name (for named variables).
    fn emit_named(&mut self, name: &str, value: ANFValue) {
        self.bindings.push(ANFBinding {
            name: name.to_string(),
            value,
        });
    }

    /// Record a parameter name so we know to use load_param for it.
    fn add_param(&mut self, name: &str) {
        self.param_names.insert(name.to_string());
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

    /// Create a sub-context for nested blocks (if/else, loops).
    /// The counter continues from the parent. Local names, param names, and aliases are shared.
    fn sub_context(&self) -> LoweringContext<'a> {
        let mut sub = LoweringContext::new(self.contract);
        sub.counter = self.counter;
        sub.param_names = self.param_names.clone();
        sub.local_names = self.local_names.clone();
        sub.local_aliases = self.local_aliases.clone();
        sub.local_byte_vars = self.local_byte_vars.clone();
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
    for stmt in stmts {
        lower_statement(stmt, ctx);
    }
}

fn lower_statement(stmt: &Statement, ctx: &mut LoweringContext) {
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
            lower_if_statement(condition, then_branch, else_branch.as_deref(), ctx);
        }
        Statement::ForStatement {
            init,
            condition,
            body,
            ..
        } => {
            lower_for_statement(init, condition, body, ctx);
        }
        Statement::ExpressionStatement { expression, .. } => {
            lower_expr_to_ref(expression, ctx);
        }
        Statement::ReturnStatement { value, .. } => {
            if let Some(v) = value {
                lower_expr_to_ref(v, ctx);
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
) {
    let cond_ref = lower_expr_to_ref(condition, ctx);

    // Lower then-block into sub-context
    let mut then_ctx = ctx.sub_context();
    lower_statements(then_branch, &mut then_ctx);
    ctx.sync_counter(&then_ctx);

    // Lower else-block into sub-context
    let mut else_ctx = ctx.sub_context();
    if let Some(else_stmts) = else_branch {
        lower_statements(else_stmts, &mut else_ctx);
    }
    ctx.sync_counter(&else_ctx);

    let then_bindings = then_ctx.bindings;
    let else_bindings = else_ctx.bindings;

    // If both branches end by reassigning the same local variable,
    // alias that variable to the if-expression result so that subsequent
    // references resolve to the branch output, not the dead initial value.
    let then_last = then_bindings.last();
    let else_last = else_bindings.last();
    let alias_local = match (then_last, else_last) {
        (Some(tl), Some(el)) if tl.name == el.name && ctx.is_local(&tl.name) => {
            Some(tl.name.clone())
        }
        _ => None,
    };

    // Propagate addOutput refs from sub-contexts: when either branch produces
    // addOutput calls, the if-expression result represents each addOutput
    // (only one branch executes at runtime).
    let then_has_outputs = !then_ctx.add_output_refs.is_empty();
    let else_has_outputs = !else_ctx.add_output_refs.is_empty();

    let if_name = ctx.emit(ANFValue::If {
        cond: cond_ref,
        then: then_bindings,
        else_branch: else_bindings,
    });

    if then_has_outputs || else_has_outputs {
        ctx.add_output_refs.push(if_name.clone());
    }

    if let Some(local_name) = alias_local {
        ctx.set_local_alias(&local_name, &if_name);
    }
}

fn lower_for_statement(
    init: &Statement,
    condition: &Expression,
    body: &[Statement],
    ctx: &mut LoweringContext,
) {
    // Extract the loop count from the for-statement.
    let count = extract_loop_count(init, condition);

    // Extract the iterator variable name
    let iter_var = if let Statement::VariableDecl { name, .. } = init {
        name.clone()
    } else {
        "_i".to_string()
    };

    // Lower body into sub-context
    let mut body_ctx = ctx.sub_context();
    lower_statements(body, &mut body_ctx);
    ctx.sync_counter(&body_ctx);

    ctx.emit(ANFValue::Loop {
        count,
        body: body_ctx.bindings,
        iter_var,
    });
}

/// Extract a compile-time loop count from a for statement.
fn extract_loop_count(init: &Statement, condition: &Expression) -> usize {
    let start_val = if let Statement::VariableDecl { init: init_expr, .. } = init {
        extract_bigint_value(init_expr)
    } else {
        None
    };

    if let Expression::BinaryExpr { op, right, .. } = condition {
        let bound_val = extract_bigint_value(right);

        if let (Some(start), Some(bound)) = (start_val, bound_val) {
            match op {
                BinaryOp::Lt => return (bound - start).max(0) as usize,
                BinaryOp::Le => return (bound - start + 1).max(0) as usize,
                BinaryOp::Gt => return (start - bound).max(0) as usize,
                BinaryOp::Ge => return (start - bound + 1).max(0) as usize,
                _ => {}
            }
        }

        // If we can at least get the bound, assume start = 0
        if let Some(bound) = bound_val {
            match op {
                BinaryOp::Lt => return bound as usize,
                BinaryOp::Le => return (bound + 1) as usize,
                _ => {}
            }
        }
    }

    0
}

fn extract_bigint_value(expr: &Expression) -> Option<i64> {
    match expr {
        Expression::BigIntLiteral { value } => Some(*value),
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
            value: serde_json::Value::Number(serde_json::Number::from(*value)),
        }),

        Expression::BoolLiteral { value } => ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::Bool(*value),
        }),

        Expression::ByteStringLiteral { value } => ctx.emit(ANFValue::LoadConst {
            value: serde_json::Value::String(value.clone()),
        }),

        Expression::Identifier { name } => lower_identifier(name, ctx),

        Expression::PropertyAccess { property } => {
            // this.txPreimage in StatefulSmartContract -> load_param (it's an implicit param, not a stored property)
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

        Expression::CallExpr { callee, args } => lower_call_expr(callee, args, ctx),

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
    let result_type = if op.as_str() == "===" || op.as_str() == "!==" {
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
    ctx.emit(ANFValue::UnaryOp {
        op: op.as_str().to_string(),
        operand: operand_ref,
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
                return ctx.emit(ANFValue::Assert { value: value_ref });
            }
            let false_ref = ctx.emit(ANFValue::LoadConst {
                value: serde_json::Value::Bool(false),
            });
            return ctx.emit(ANFValue::Assert { value: false_ref });
        }
    }

    // checkPreimage(preimage) -> special node
    if let Expression::Identifier { name } = callee {
        if name == "checkPreimage" {
            if !args.is_empty() {
                let preimage_ref = lower_expr_to_ref(&args[0], ctx);
                return ctx.emit(ANFValue::CheckPreimage {
                    preimage: preimage_ref,
                });
            }
        }
    }

    // this.addOutput(satoshis, val1, val2, ...) -> special node (via PropertyAccess)
    if let Expression::PropertyAccess { property } = callee {
        if property == "addOutput" {
            let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
            let satoshis = arg_refs.first().cloned().unwrap_or_default();
            let mut state_values = if arg_refs.len() > 1 { arg_refs[1..].to_vec() } else { Vec::new() };
            // For InductiveSmartContract, auto-append internal field values.
            // The internal fields have already been updated (update_prop) before the
            // developer's body, so load_prop returns the correct new-generation values.
            if ctx.contract.parent_class == "InductiveSmartContract" {
                let genesis_ref = ctx.emit(ANFValue::LoadProp { name: "_genesisOutpoint".to_string() });
                let parent_ref = ctx.emit(ANFValue::LoadProp { name: "_parentOutpoint".to_string() });
                let grandparent_ref = ctx.emit(ANFValue::LoadProp { name: "_grandparentOutpoint".to_string() });
                state_values.push(genesis_ref);
                state_values.push(parent_ref);
                state_values.push(grandparent_ref);
            }
            let preimage = ctx.emit(ANFValue::LoadParam { name: "txPreimage".to_string() });
            let r = ctx.emit(ANFValue::AddOutput { satoshis, state_values, preimage });
            ctx.add_output_refs.push(r.clone());
            return r;
        }
    }
    // this.addOutput(satoshis, val1, val2, ...) -> special node (via MemberExpr with this)
    if let Expression::MemberExpr { object, property } = callee {
        if let Expression::Identifier { name } = object.as_ref() {
            if name == "this" && property == "addOutput" {
                let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
                let satoshis = arg_refs.first().cloned().unwrap_or_default();
                let mut state_values = if arg_refs.len() > 1 { arg_refs[1..].to_vec() } else { Vec::new() };
                // For InductiveSmartContract, auto-append internal field values.
                if ctx.contract.parent_class == "InductiveSmartContract" {
                    let genesis_ref = ctx.emit(ANFValue::LoadProp { name: "_genesisOutpoint".to_string() });
                    let parent_ref = ctx.emit(ANFValue::LoadProp { name: "_parentOutpoint".to_string() });
                    let grandparent_ref = ctx.emit(ANFValue::LoadProp { name: "_grandparentOutpoint".to_string() });
                    state_values.push(genesis_ref);
                    state_values.push(parent_ref);
                    state_values.push(grandparent_ref);
                }
                let preimage = ctx.emit(ANFValue::LoadParam { name: "txPreimage".to_string() });
                let r = ctx.emit(ANFValue::AddOutput { satoshis, state_values, preimage });
                ctx.add_output_refs.push(r.clone());
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

    // this.method(...) -> method_call (via PropertyAccess)
    if let Expression::PropertyAccess { property } = callee {
        let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
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

    // Direct function call: sha256(x), checkSig(sig, pk), etc.
    if let Expression::Identifier { name } = callee {
        let arg_refs: Vec<String> = args.iter().map(|a| lower_expr_to_ref(a, ctx)).collect();
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

fn lower_ternary_expr(
    condition: &Expression,
    consequent: &Expression,
    alternate: &Expression,
    ctx: &mut LoweringContext,
) -> String {
    let cond_ref = lower_expr_to_ref(condition, ctx);

    let mut then_ctx = ctx.sub_context();
    lower_expr_to_ref(consequent, &mut then_ctx);
    ctx.sync_counter(&then_ctx);

    let mut else_ctx = ctx.sub_context();
    lower_expr_to_ref(alternate, &mut else_ctx);
    ctx.sync_counter(&else_ctx);

    ctx.emit(ANFValue::If {
        cond: cond_ref,
        then: then_ctx.bindings,
        else_branch: else_ctx.bindings,
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
    "RabinSig", "RabinPubKey", "Point",
];

/// Builtin functions that return byte-typed values.
const BYTE_RETURNING_FUNCTIONS: &[&str] = &[
    "sha256", "ripemd160", "hash160", "hash256", "cat", "num2bin", "int2str",
    "reverseBytes", "substr", "left", "right",
    "ecAdd", "ecMul", "ecMulGen", "ecNegate", "ecMakePoint", "ecEncodeCompressed",
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

        Expression::CallExpr { callee, .. } => {
            if let Expression::Identifier { name } = callee.as_ref() {
                if BYTE_RETURNING_FUNCTIONS.contains(&name.as_str()) {
                    return true;
                }
            }
            false
        }

        _ => false,
    }
}

/// Look up the type of a method parameter by name across all contract methods.
fn get_param_type(name: &str, ctx: &LoweringContext) -> Option<String> {
    // Check constructor params
    for p in &ctx.contract.constructor.params {
        if p.name == name {
            return Some(type_node_to_string(&p.param_type));
        }
    }
    // Check method params
    for method in &ctx.contract.methods {
        for p in &method.params {
            if p.name == name {
                return Some(type_node_to_string(&p.param_type));
            }
        }
    }
    None
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
// State mutation analysis for StatefulSmartContract
// ---------------------------------------------------------------------------

/// Determine whether a method mutates any mutable (non-readonly) property.
/// Conservative: if ANY code path can mutate state, returns true.
fn method_mutates_state(method: &MethodNode, contract: &ContractNode) -> bool {
    let mutable_prop_names: HashSet<String> = contract
        .properties
        .iter()
        .filter(|p| !p.readonly)
        .map(|p| p.name.clone())
        .collect();
    if mutable_prop_names.is_empty() {
        return false;
    }
    body_mutates_state(&method.body, &mutable_prop_names)
}

fn body_mutates_state(stmts: &[Statement], mutable_props: &HashSet<String>) -> bool {
    for stmt in stmts {
        if stmt_mutates_state(stmt, mutable_props) {
            return true;
        }
    }
    false
}

fn stmt_mutates_state(stmt: &Statement, mutable_props: &HashSet<String>) -> bool {
    match stmt {
        Statement::Assignment { target, .. } => {
            if let Expression::PropertyAccess { property } = target {
                if mutable_props.contains(property) {
                    return true;
                }
            }
            false
        }
        Statement::ExpressionStatement { expression, .. } => {
            expr_mutates_state(expression, mutable_props)
        }
        Statement::IfStatement {
            then_branch,
            else_branch,
            ..
        } => {
            body_mutates_state(then_branch, mutable_props)
                || else_branch
                    .as_ref()
                    .map_or(false, |e| body_mutates_state(e, mutable_props))
        }
        Statement::ForStatement { body, .. } => body_mutates_state(body, mutable_props),
        _ => false,
    }
}

fn expr_mutates_state(expr: &Expression, mutable_props: &HashSet<String>) -> bool {
    match expr {
        Expression::IncrementExpr { operand, .. } | Expression::DecrementExpr { operand, .. } => {
            if let Expression::PropertyAccess { property } = operand.as_ref() {
                if mutable_props.contains(property) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// addOutput detection for determining change output necessity
// ---------------------------------------------------------------------------

/// Check if a method body contains any this.addOutput() calls.
fn method_has_add_output(method: &MethodNode) -> bool {
    body_has_add_output(&method.body)
}

fn body_has_add_output(stmts: &[Statement]) -> bool {
    for stmt in stmts {
        if stmt_has_add_output(stmt) {
            return true;
        }
    }
    false
}

fn stmt_has_add_output(stmt: &Statement) -> bool {
    match stmt {
        Statement::ExpressionStatement { expression, .. } => expr_has_add_output(expression),
        Statement::IfStatement {
            then_branch,
            else_branch,
            ..
        } => {
            body_has_add_output(then_branch)
                || else_branch
                    .as_ref()
                    .map_or(false, |e| body_has_add_output(e))
        }
        Statement::ForStatement { body, .. } => body_has_add_output(body),
        _ => false,
    }
}

fn expr_has_add_output(expr: &Expression) -> bool {
    if let Expression::CallExpr { callee, .. } = expr {
        if let Expression::PropertyAccess { property } = callee.as_ref() {
            if property == "addOutput" {
                return true;
            }
        }
        if let Expression::MemberExpr { object, property } = callee.as_ref() {
            if let Expression::Identifier { name } = object.as_ref() {
                if name == "this" && property == "addOutput" {
                    return true;
                }
            }
        }
    }
    false
}
