//! Pass 5: Stack Lower -- converts ANF IR to Stack IR.
//!
//! The fundamental challenge: ANF uses named temporaries but Bitcoin Script
//! operates on an anonymous stack. We maintain a "stack map" that tracks
//! which named value lives at which stack position, then emit PICK/ROLL/DUP
//! operations to shuttle values to the top when they are needed.
//!
//! This matches the TypeScript reference compiler and aligned Go compiler:
//! - Private methods are inlined at call sites rather than compiled separately
//! - Constructor is skipped
//! - @ref: aliases are handled via PICK (non-consuming copy)
//! - @this is a compile-time placeholder (push 0)
//! - super() is a no-op at stack level

use std::collections::{HashMap, HashSet};

use crate::ir::{ANFBinding, ANFMethod, ANFProgram, ANFProperty, ANFValue, ConstValue};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_STACK_DEPTH: usize = 800;

// ---------------------------------------------------------------------------
// Stack IR types
// ---------------------------------------------------------------------------

/// A single stack-machine operation.
#[derive(Debug, Clone)]
pub enum StackOp {
    Push(PushValue),
    Dup,
    Swap,
    Roll { depth: usize },
    Pick { depth: usize },
    Drop,
    Nip,
    Over,
    Rot,
    Tuck,
    Opcode(String),
    If {
        then_ops: Vec<StackOp>,
        else_ops: Vec<StackOp>,
    },
    Placeholder {
        param_index: usize,
        param_name: String,
    },
    PushCodeSepIndex,
}

/// Typed value for push operations.
#[derive(Debug, Clone)]
pub enum PushValue {
    Bool(bool),
    Int(i128),
    Bytes(Vec<u8>),
}

/// A stack-lowered method.
#[derive(Debug, Clone)]
pub struct StackMethod {
    pub name: String,
    pub ops: Vec<StackOp>,
    pub max_stack_depth: usize,
}

// ---------------------------------------------------------------------------
// Builtin function -> opcode mapping
// ---------------------------------------------------------------------------

fn is_ec_builtin(name: &str) -> bool {
    matches!(
        name,
        "ecAdd"
            | "ecMul"
            | "ecMulGen"
            | "ecNegate"
            | "ecOnCurve"
            | "ecModReduce"
            | "ecEncodeCompressed"
            | "ecMakePoint"
            | "ecPointX"
            | "ecPointY"
    )
}

fn builtin_opcodes(name: &str) -> Option<Vec<&'static str>> {
    match name {
        "sha256" => Some(vec!["OP_SHA256"]),
        "ripemd160" => Some(vec!["OP_RIPEMD160"]),
        "hash160" => Some(vec!["OP_HASH160"]),
        "hash256" => Some(vec!["OP_HASH256"]),
        "checkSig" => Some(vec!["OP_CHECKSIG"]),
        "checkMultiSig" => Some(vec!["OP_CHECKMULTISIG"]),
        "len" => Some(vec!["OP_SIZE"]),
        "cat" => Some(vec!["OP_CAT"]),
        "num2bin" => Some(vec!["OP_NUM2BIN"]),
        "bin2num" => Some(vec!["OP_BIN2NUM"]),
        "abs" => Some(vec!["OP_ABS"]),
        "min" => Some(vec!["OP_MIN"]),
        "max" => Some(vec!["OP_MAX"]),
        "within" => Some(vec!["OP_WITHIN"]),
        "split" => Some(vec!["OP_SPLIT"]),
        "left" => Some(vec!["OP_SPLIT", "OP_DROP"]),
        "int2str" => Some(vec!["OP_NUM2BIN"]),
        "bool" => Some(vec!["OP_0NOTEQUAL"]),
        "unpack" => Some(vec!["OP_BIN2NUM"]),
        _ => None,
    }
}

fn binop_opcodes(op: &str) -> Option<Vec<&'static str>> {
    match op {
        "+" => Some(vec!["OP_ADD"]),
        "-" => Some(vec!["OP_SUB"]),
        "*" => Some(vec!["OP_MUL"]),
        "/" => Some(vec!["OP_DIV"]),
        "%" => Some(vec!["OP_MOD"]),
        "===" => Some(vec!["OP_NUMEQUAL"]),
        "!==" => Some(vec!["OP_NUMEQUAL", "OP_NOT"]),
        "<" => Some(vec!["OP_LESSTHAN"]),
        ">" => Some(vec!["OP_GREATERTHAN"]),
        "<=" => Some(vec!["OP_LESSTHANOREQUAL"]),
        ">=" => Some(vec!["OP_GREATERTHANOREQUAL"]),
        "&&" => Some(vec!["OP_BOOLAND"]),
        "||" => Some(vec!["OP_BOOLOR"]),
        "&" => Some(vec!["OP_AND"]),
        "|" => Some(vec!["OP_OR"]),
        "^" => Some(vec!["OP_XOR"]),
        "<<" => Some(vec!["OP_LSHIFT"]),
        ">>" => Some(vec!["OP_RSHIFT"]),
        _ => None,
    }
}

fn unaryop_opcodes(op: &str) -> Option<Vec<&'static str>> {
    match op {
        "!" => Some(vec!["OP_NOT"]),
        "-" => Some(vec!["OP_NEGATE"]),
        "~" => Some(vec!["OP_INVERT"]),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Stack map
// ---------------------------------------------------------------------------

/// Tracks named values on the stack. Index 0 is the bottom; last is the top.
/// Empty string means anonymous/consumed slot.
#[derive(Debug, Clone)]
struct StackMap {
    slots: Vec<String>,
}

impl StackMap {
    fn new(initial: &[String]) -> Self {
        StackMap {
            slots: initial.to_vec(),
        }
    }

    fn depth(&self) -> usize {
        self.slots.len()
    }

    fn push(&mut self, name: &str) {
        self.slots.push(name.to_string());
    }

    fn pop(&mut self) -> String {
        self.slots.pop().expect("stack underflow")
    }

    fn find_depth(&self, name: &str) -> Option<usize> {
        for (i, slot) in self.slots.iter().enumerate().rev() {
            if slot == name {
                return Some(self.slots.len() - 1 - i);
            }
        }
        None
    }

    fn has(&self, name: &str) -> bool {
        self.slots.iter().any(|s| s == name)
    }

    fn remove_at_depth(&mut self, depth_from_top: usize) -> String {
        let index = self.slots.len() - 1 - depth_from_top;
        self.slots.remove(index)
    }

    fn peek_at_depth(&self, depth_from_top: usize) -> &str {
        let index = self.slots.len() - 1 - depth_from_top;
        &self.slots[index]
    }

    fn rename_at_depth(&mut self, depth_from_top: usize, new_name: &str) {
        let idx = self.slots.len() - 1 - depth_from_top;
        self.slots[idx] = new_name.to_string();
    }

    fn swap(&mut self) {
        let n = self.slots.len();
        assert!(n >= 2, "stack underflow on swap");
        self.slots.swap(n - 1, n - 2);
    }

    fn dup(&mut self) {
        assert!(!self.slots.is_empty(), "stack underflow on dup");
        let top = self.slots.last().unwrap().clone();
        self.slots.push(top);
    }

    /// Get the set of all non-empty slot names.
    fn named_slots(&self) -> HashSet<String> {
        self.slots.iter().filter(|s| !s.is_empty()).cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Use analysis
// ---------------------------------------------------------------------------

fn compute_last_uses(bindings: &[ANFBinding]) -> HashMap<String, usize> {
    let mut last_use = HashMap::new();
    for (i, binding) in bindings.iter().enumerate() {
        for r in collect_refs(&binding.value) {
            last_use.insert(r, i);
        }
    }
    last_use
}

fn collect_refs(value: &ANFValue) -> Vec<String> {
    let mut refs = Vec::new();
    match value {
        ANFValue::LoadParam { name } => {
            // Track param name so last-use analysis keeps the param on the stack
            // (via PICK) until its final load_param, then consumes it (via ROLL).
            refs.push(name.clone());
        }
        ANFValue::LoadProp { .. }
        | ANFValue::GetStateScript { .. } => {}

        ANFValue::LoadConst { value: v } => {
            // load_const with @ref: values reference another binding
            if let Some(s) = v.as_str() {
                if s.len() > 5 && &s[..5] == "@ref:" {
                    refs.push(s[5..].to_string());
                }
            }
        }

        ANFValue::BinOp { left, right, .. } => {
            refs.push(left.clone());
            refs.push(right.clone());
        }
        ANFValue::UnaryOp { operand, .. } => {
            refs.push(operand.clone());
        }
        ANFValue::Call { args, .. } => {
            refs.extend(args.iter().cloned());
        }
        ANFValue::MethodCall { object, args, .. } => {
            refs.push(object.clone());
            refs.extend(args.iter().cloned());
        }
        ANFValue::If {
            cond,
            then,
            else_branch,
        } => {
            refs.push(cond.clone());
            for b in then {
                refs.extend(collect_refs(&b.value));
            }
            for b in else_branch {
                refs.extend(collect_refs(&b.value));
            }
        }
        ANFValue::Loop { body, .. } => {
            for b in body {
                refs.extend(collect_refs(&b.value));
            }
        }
        ANFValue::Assert { value } => {
            refs.push(value.clone());
        }
        ANFValue::UpdateProp { value, .. } => {
            refs.push(value.clone());
        }
        ANFValue::CheckPreimage { preimage } => {
            refs.push(preimage.clone());
        }
        ANFValue::DeserializeState { preimage } => {
            refs.push(preimage.clone());
        }
        ANFValue::AddOutput { satoshis, state_values, preimage } => {
            refs.push(satoshis.clone());
            refs.extend(state_values.iter().cloned());
            if !preimage.is_empty() {
                refs.push(preimage.clone());
            }
        }
        ANFValue::AddRawOutput { satoshis, script_bytes } => {
            refs.push(satoshis.clone());
            refs.push(script_bytes.clone());
        }
        ANFValue::ArrayLiteral { elements } => {
            refs.extend(elements.iter().cloned());
        }
    }
    refs
}

// ---------------------------------------------------------------------------
// Lowering context
// ---------------------------------------------------------------------------

struct LoweringContext {
    sm: StackMap,
    ops: Vec<StackOp>,
    max_depth: usize,
    properties: Vec<ANFProperty>,
    private_methods: HashMap<String, ANFMethod>,
    /// Binding names defined in the current lowerBindings scope.
    /// Used by @ref: handler to decide whether to consume (local) or copy (outer-scope).
    local_bindings: HashSet<String>,
    /// Parent-scope refs that must not be consumed (used after current if-branch).
    outer_protected_refs: Option<HashSet<String>>,
    /// True when executing inside an if-branch. update_prop skips old-value
    /// removal so that the same-property detection in lower_if can handle it.
    inside_branch: bool,
}

impl LoweringContext {
    fn new(params: &[String], properties: &[ANFProperty]) -> Self {
        let mut ctx = LoweringContext {
            sm: StackMap::new(params),
            ops: Vec::new(),
            max_depth: 0,
            properties: properties.to_vec(),
            private_methods: HashMap::new(),
            local_bindings: HashSet::new(),
            outer_protected_refs: None,
            inside_branch: false,
        };
        ctx.track_depth();
        ctx
    }

    fn track_depth(&mut self) {
        if self.sm.depth() > self.max_depth {
            self.max_depth = self.sm.depth();
        }
    }

    fn emit_op(&mut self, op: StackOp) {
        self.ops.push(op);
        self.track_depth();
    }

    /// Emit a Bitcoin varint encoding of the length on top of the stack.
    ///
    /// Expects stack: `[..., script, len]`
    /// Leaves stack:  `[..., script, varint_bytes]`
    ///
    /// OP_NUM2BIN uses sign-magnitude encoding where values 128-255 need 2 bytes
    /// (sign bit). To produce a correct 1-byte unsigned varint, we use
    /// OP_NUM2BIN 2 then SPLIT to extract only the low byte.
    /// Similarly for 2-byte unsigned varint, we use OP_NUM2BIN 4 then SPLIT.
    fn emit_varint_encoding(&mut self) {
        // Stack: [..., script, len]
        self.emit_op(StackOp::Dup); // [script, len, len]
        self.sm.dup();
        self.emit_op(StackOp::Push(PushValue::Int(253))); // [script, len, len, 253]
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_LESSTHAN".into())); // [script, len, isSmall]
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_IF".into()));
        self.sm.pop(); // pop condition

        // Then: 1-byte varint (len < 253)
        // Use NUM2BIN 2 to avoid sign-magnitude issue for values 128-252,
        // then take only the first (low) byte via SPLIT.
        self.emit_op(StackOp::Push(PushValue::Int(2))); // [script, len, 2]
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".into())); // [script, len_2bytes]
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(1))); // [script, len_2bytes, 1]
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".into())); // [script, lowByte, highByte]
        self.sm.pop();
        self.sm.pop();
        self.sm.push(""); // lowByte
        self.sm.push(""); // highByte
        self.emit_op(StackOp::Drop); // [script, lowByte]
        self.sm.pop();

        self.emit_op(StackOp::Opcode("OP_ELSE".into()));

        // Else: 0xfd + 2-byte LE varint (len >= 253)
        // Use NUM2BIN 4 to avoid sign-magnitude issue for values >= 32768,
        // then take only the first 2 (low) bytes via SPLIT.
        self.emit_op(StackOp::Push(PushValue::Int(4))); // [script, len, 4]
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".into())); // [script, len_4bytes]
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(2))); // [script, len_4bytes, 2]
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".into())); // [script, low2bytes, high2bytes]
        self.sm.pop();
        self.sm.pop();
        self.sm.push(""); // low2bytes
        self.sm.push(""); // high2bytes
        self.emit_op(StackOp::Drop); // [script, low2bytes]
        self.sm.pop();
        self.emit_op(StackOp::Push(PushValue::Bytes(vec![0xfd])));
        self.sm.push("");
        self.emit_op(StackOp::Swap);
        self.sm.swap();
        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_ENDIF".into()));
        // --- Stack: [..., script, varint] ---
    }

    /// Emit push-data encoding for a ByteString value on top of the stack.
    ///
    /// Expects stack: [..., bs_value]
    /// Leaves stack:  [..., pushdata_encoded_value]
    fn emit_push_data_encode(&mut self) {
        self.emit_op(StackOp::Opcode("OP_SIZE".into()));
        self.sm.push("");
        self.emit_op(StackOp::Dup);
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(76)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_LESSTHAN".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_IF".into()));
        self.sm.pop();
        let sm_after_outer_if = self.sm.clone();

        // THEN: len <= 75
        self.emit_op(StackOp::Push(PushValue::Int(2)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(1)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");
        self.emit_op(StackOp::Drop); self.sm.pop();
        self.emit_op(StackOp::Swap); self.sm.swap();
        self.sm.pop(); self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.push("");
        let sm_end_target = self.sm.clone();

        self.emit_op(StackOp::Opcode("OP_ELSE".into()));
        self.sm = sm_after_outer_if.clone();

        self.emit_op(StackOp::Dup);
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(256)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_LESSTHAN".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_IF".into()));
        self.sm.pop();
        let sm_after_inner_if = self.sm.clone();

        // THEN: 76-255 → 0x4c + 1-byte
        self.emit_op(StackOp::Push(PushValue::Int(2)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(1)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");
        self.emit_op(StackOp::Drop); self.sm.pop();
        self.emit_op(StackOp::Push(PushValue::Bytes(vec![0x4c])));
        self.sm.push("");
        self.emit_op(StackOp::Swap); self.sm.swap();
        self.sm.pop(); self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.push("");
        self.emit_op(StackOp::Swap); self.sm.swap();
        self.sm.pop(); self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_ELSE".into()));
        self.sm = sm_after_inner_if;

        // ELSE: >= 256 → 0x4d + 2-byte LE
        self.emit_op(StackOp::Push(PushValue::Int(4)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(2)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");
        self.emit_op(StackOp::Drop); self.sm.pop();
        self.emit_op(StackOp::Push(PushValue::Bytes(vec![0x4d])));
        self.sm.push("");
        self.emit_op(StackOp::Swap); self.sm.swap();
        self.sm.pop(); self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.push("");
        self.emit_op(StackOp::Swap); self.sm.swap();
        self.sm.pop(); self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_ENDIF".into()));
        self.emit_op(StackOp::Opcode("OP_ENDIF".into()));
        self.sm = sm_end_target;
    }

    /// Emit push-data decoding for a ByteString state field.
    ///
    /// Expects stack: [..., state_bytes]
    /// Leaves stack:  [..., data, remaining_state]
    fn emit_push_data_decode(&mut self) {
        self.emit_op(StackOp::Push(PushValue::Int(1)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");
        self.emit_op(StackOp::Swap); self.sm.swap();
        self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
        self.emit_op(StackOp::Dup);
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(76)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_LESSTHAN".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_IF".into()));
        self.sm.pop();
        let sm_after_outer_if = self.sm.clone();

        // THEN: fb < 76 → direct length
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");
        let sm_end_target = self.sm.clone();

        self.emit_op(StackOp::Opcode("OP_ELSE".into()));
        self.sm = sm_after_outer_if.clone();

        self.emit_op(StackOp::Dup);
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(77)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUMEQUAL".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_IF".into()));
        self.sm.pop();
        let sm_after_inner_if = self.sm.clone();

        // THEN: fb == 77 → 2-byte LE
        self.emit_op(StackOp::Drop); self.sm.pop();
        self.emit_op(StackOp::Push(PushValue::Int(2)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");
        self.emit_op(StackOp::Swap); self.sm.swap();
        self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_ELSE".into()));
        self.sm = sm_after_inner_if;

        // ELSE: fb == 76 → 1-byte
        self.emit_op(StackOp::Drop); self.sm.pop();
        self.emit_op(StackOp::Push(PushValue::Int(1)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");
        self.emit_op(StackOp::Swap); self.sm.swap();
        self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_ENDIF".into()));
        self.emit_op(StackOp::Opcode("OP_ENDIF".into()));
        self.sm = sm_end_target;
    }

    fn is_last_use(&self, name: &str, current_index: usize, last_uses: &HashMap<String, usize>) -> bool {
        match last_uses.get(name) {
            None => true,
            Some(&last) => last <= current_index,
        }
    }

    fn bring_to_top(&mut self, name: &str, consume: bool) {
        let depth = self
            .sm
            .find_depth(name)
            .unwrap_or_else(|| panic!("value '{}' not found on stack", name));

        if depth == 0 {
            if !consume {
                self.emit_op(StackOp::Dup);
                self.sm.dup();
            }
            return;
        }

        if depth == 1 && consume {
            self.emit_op(StackOp::Swap);
            self.sm.swap();
            return;
        }

        if consume {
            if depth == 2 {
                self.emit_op(StackOp::Rot);
                let removed = self.sm.remove_at_depth(2);
                self.sm.push(&removed);
            } else {
                self.emit_op(StackOp::Push(PushValue::Int(depth as i128)));
                self.sm.push(""); // temporary depth literal
                self.emit_op(StackOp::Roll { depth });
                self.sm.pop(); // remove depth literal
                let rolled = self.sm.remove_at_depth(depth);
                self.sm.push(&rolled);
            }
        } else {
            if depth == 1 {
                self.emit_op(StackOp::Over);
                let picked = self.sm.peek_at_depth(1).to_string();
                self.sm.push(&picked);
            } else {
                self.emit_op(StackOp::Push(PushValue::Int(depth as i128)));
                self.sm.push(""); // temporary
                self.emit_op(StackOp::Pick { depth });
                self.sm.pop(); // remove depth literal
                let picked = self.sm.peek_at_depth(depth).to_string();
                self.sm.push(&picked);
            }
        }

        self.track_depth();
    }

    // -----------------------------------------------------------------------
    // Lower bindings
    // -----------------------------------------------------------------------

    fn lower_bindings(&mut self, bindings: &[ANFBinding], terminal_assert: bool) {
        self.local_bindings = bindings.iter().map(|b| b.name.clone()).collect();
        let mut last_uses = compute_last_uses(bindings);

        // Protect parent-scope refs that are still needed after this scope
        if let Some(ref protected) = self.outer_protected_refs {
            for r in protected {
                last_uses.insert(r.clone(), bindings.len());
            }
        }

        // Find the terminal binding index (if terminal_assert is set).
        // If the last binding is an 'if' whose branches end in asserts,
        // that 'if' is the terminal point (not an earlier standalone assert).
        let mut last_assert_idx: isize = -1;
        let mut terminal_if_idx: isize = -1;
        if terminal_assert {
            let last_binding = bindings.last();
            if let Some(b) = last_binding {
                if matches!(&b.value, ANFValue::If { .. }) {
                    terminal_if_idx = (bindings.len() - 1) as isize;
                } else {
                    for i in (0..bindings.len()).rev() {
                        if matches!(&bindings[i].value, ANFValue::Assert { .. }) {
                            last_assert_idx = i as isize;
                            break;
                        }
                    }
                }
            }
        }

        for (i, binding) in bindings.iter().enumerate() {
            if matches!(&binding.value, ANFValue::Assert { .. }) && i as isize == last_assert_idx {
                // Terminal assert: leave value on stack instead of OP_VERIFY
                if let ANFValue::Assert { value } = &binding.value {
                    self.lower_assert(value, i, &last_uses, true);
                }
            } else if matches!(&binding.value, ANFValue::If { .. }) && i as isize == terminal_if_idx {
                // Terminal if: propagate terminalAssert into both branches
                if let ANFValue::If { cond, then, else_branch } = &binding.value {
                    self.lower_if(&binding.name, cond, then, else_branch, i, &last_uses, true);
                }
            } else {
                self.lower_binding(binding, i, &last_uses);
            }
        }
    }

    fn lower_binding(
        &mut self,
        binding: &ANFBinding,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        let name = &binding.name;
        match &binding.value {
            ANFValue::LoadParam {
                name: param_name, ..
            } => {
                self.lower_load_param(name, param_name, binding_index, last_uses);
            }
            ANFValue::LoadProp {
                name: prop_name, ..
            } => {
                self.lower_load_prop(name, prop_name);
            }
            ANFValue::LoadConst { .. } => {
                self.lower_load_const(name, &binding.value, binding_index, last_uses);
            }
            ANFValue::BinOp {
                op, left, right, result_type, ..
            } => {
                self.lower_bin_op(name, op, left, right, binding_index, last_uses, result_type.as_deref());
            }
            ANFValue::UnaryOp { op, operand, .. } => {
                self.lower_unary_op(name, op, operand, binding_index, last_uses);
            }
            ANFValue::Call {
                func: func_name,
                args,
            } => {
                self.lower_call(name, func_name, args, binding_index, last_uses);
            }
            ANFValue::MethodCall {
                object,
                method,
                args,
            } => {
                self.lower_method_call(name, object, method, args, binding_index, last_uses);
            }
            ANFValue::If {
                cond,
                then,
                else_branch,
            } => {
                self.lower_if(name, cond, then, else_branch, binding_index, last_uses, false);
            }
            ANFValue::Loop {
                count,
                body,
                iter_var,
            } => {
                self.lower_loop(name, *count, body, iter_var);
            }
            ANFValue::Assert { value } => {
                self.lower_assert(value, binding_index, last_uses, false);
            }
            ANFValue::UpdateProp {
                name: prop_name,
                value,
            } => {
                self.lower_update_prop(prop_name, value, binding_index, last_uses);
            }
            ANFValue::GetStateScript {} => {
                self.lower_get_state_script(name);
            }
            ANFValue::CheckPreimage { preimage } => {
                self.lower_check_preimage(name, preimage, binding_index, last_uses);
            }
            ANFValue::DeserializeState { preimage } => {
                self.lower_deserialize_state(preimage, binding_index, last_uses);
            }
            ANFValue::AddOutput { satoshis, state_values, preimage } => {
                self.lower_add_output(name, satoshis, state_values, preimage, binding_index, last_uses);
            }
            ANFValue::AddRawOutput { satoshis, script_bytes } => {
                self.lower_add_raw_output(name, satoshis, script_bytes, binding_index, last_uses);
            }
            ANFValue::ArrayLiteral { elements } => {
                self.lower_array_literal(name, elements, binding_index, last_uses);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Individual lowering methods
    // -----------------------------------------------------------------------

    fn lower_load_param(
        &mut self,
        binding_name: &str,
        param_name: &str,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        if self.sm.has(param_name) {
            let is_last = self.is_last_use(param_name, binding_index, last_uses);
            self.bring_to_top(param_name, is_last);
            self.sm.pop();
            self.sm.push(binding_name);
        } else {
            self.emit_op(StackOp::Push(PushValue::Int(0)));
            self.sm.push(binding_name);
        }
    }

    fn lower_load_prop(&mut self, binding_name: &str, prop_name: &str) {
        let prop = self.properties.iter().find(|p| p.name == prop_name).cloned();

        if self.sm.has(prop_name) {
            // Property has been updated (via update_prop) — use the stack value.
            // Must check this BEFORE initial_value — after update_prop, we need the
            // updated value, not the original constant.
            self.bring_to_top(prop_name, false);
            self.sm.pop();
        } else if let Some(ref p) = prop {
            if let Some(ref val) = p.initial_value {
                self.push_json_value(val);
            } else {
                // Property value will be provided at deployment time; emit a placeholder.
                // The emitter records byte offsets so the SDK can splice in real values.
                let param_index = self
                    .properties
                    .iter()
                    .position(|p2| p2.name == prop_name)
                    .unwrap_or(0);
                self.emit_op(StackOp::Placeholder {
                    param_index,
                    param_name: prop_name.to_string(),
                });
            }
        } else {
            // Property not found and not on stack — emit placeholder with index 0.
            let param_index = self
                .properties
                .iter()
                .position(|p2| p2.name == prop_name)
                .unwrap_or(0);
            self.emit_op(StackOp::Placeholder {
                param_index,
                param_name: prop_name.to_string(),
            });
        }
        self.sm.push(binding_name);
    }

    fn push_json_value(&mut self, val: &serde_json::Value) {
        match val {
            serde_json::Value::Bool(b) => {
                self.emit_op(StackOp::Push(PushValue::Bool(*b)));
            }
            serde_json::Value::Number(n) => {
                let i = n.as_i64().map(|v| v as i128).unwrap_or(0);
                self.emit_op(StackOp::Push(PushValue::Int(i)));
            }
            serde_json::Value::String(s) => {
                let bytes = hex_to_bytes(s);
                self.emit_op(StackOp::Push(PushValue::Bytes(bytes)));
            }
            _ => {
                self.emit_op(StackOp::Push(PushValue::Int(0)));
            }
        }
    }

    fn lower_load_const(&mut self, binding_name: &str, value: &ANFValue, binding_index: usize, last_uses: &HashMap<String, usize>) {
        // Handle @ref: aliases (ANF variable aliasing)
        // When a load_const has a string value starting with "@ref:", it's an alias
        // to another binding. We bring that value to the top via PICK (non-consuming)
        // unless this is the last use, in which case we consume it via ROLL.
        if let Some(ConstValue::Str(ref s)) = value.const_value() {
            if s.len() > 5 && &s[..5] == "@ref:" {
                let ref_name = &s[5..];
                if self.sm.has(ref_name) {
                    // Only consume (ROLL) if the ref target is a local binding in the
                    // current scope. Outer-scope refs must be copied (PICK) so that the
                    // parent stackMap stays in sync (critical for IfElse branches and
                    // BoundedLoop iterations).
                    let consume = self.local_bindings.contains(ref_name)
                        && self.is_last_use(ref_name, binding_index, last_uses);
                    self.bring_to_top(ref_name, consume);
                    self.sm.pop();
                    self.sm.push(binding_name);
                } else {
                    // Referenced value not on stack -- push a placeholder
                    self.emit_op(StackOp::Push(PushValue::Int(0)));
                    self.sm.push(binding_name);
                }
                return;
            }
            // Handle @this marker -- compile-time concept, not a runtime value
            if s == "@this" {
                self.emit_op(StackOp::Push(PushValue::Int(0)));
                self.sm.push(binding_name);
                return;
            }
        }

        match value.const_value() {
            Some(ConstValue::Bool(b)) => {
                self.emit_op(StackOp::Push(PushValue::Bool(b)));
            }
            Some(ConstValue::Int(n)) => {
                self.emit_op(StackOp::Push(PushValue::Int(n)));
            }
            Some(ConstValue::Str(s)) => {
                let bytes = hex_to_bytes(&s);
                self.emit_op(StackOp::Push(PushValue::Bytes(bytes)));
            }
            None => {
                self.emit_op(StackOp::Push(PushValue::Int(0)));
            }
        }
        self.sm.push(binding_name);
    }

    fn lower_bin_op(
        &mut self,
        binding_name: &str,
        op: &str,
        left: &str,
        right: &str,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
        result_type: Option<&str>,
    ) {
        let left_is_last = self.is_last_use(left, binding_index, last_uses);
        self.bring_to_top(left, left_is_last);

        let right_is_last = self.is_last_use(right, binding_index, last_uses);
        self.bring_to_top(right, right_is_last);

        self.sm.pop();
        self.sm.pop();

        // For equality operators, choose OP_EQUAL vs OP_NUMEQUAL based on operand type.
        // For addition, choose OP_CAT vs OP_ADD based on operand type.
        if result_type == Some("bytes") && op == "+" {
            self.emit_op(StackOp::Opcode("OP_CAT".to_string()));
        } else if result_type == Some("bytes") && (op == "===" || op == "!==") {
            self.emit_op(StackOp::Opcode("OP_EQUAL".to_string()));
            if op == "!==" {
                self.emit_op(StackOp::Opcode("OP_NOT".to_string()));
            }
        } else {
            let codes = binop_opcodes(op)
                .unwrap_or_else(|| panic!("unknown binary operator: {}", op));
            for code in codes {
                self.emit_op(StackOp::Opcode(code.to_string()));
            }
        }

        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_unary_op(
        &mut self,
        binding_name: &str,
        op: &str,
        operand: &str,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        let is_last = self.is_last_use(operand, binding_index, last_uses);
        self.bring_to_top(operand, is_last);

        self.sm.pop();

        let codes = unaryop_opcodes(op)
            .unwrap_or_else(|| panic!("unknown unary operator: {}", op));
        for code in codes {
            self.emit_op(StackOp::Opcode(code.to_string()));
        }

        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_call(
        &mut self,
        binding_name: &str,
        func_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // Special handling for assert
        if func_name == "assert" {
            if !args.is_empty() {
                let is_last = self.is_last_use(&args[0], binding_index, last_uses);
                self.bring_to_top(&args[0], is_last);
                self.sm.pop();
                self.emit_op(StackOp::Opcode("OP_VERIFY".to_string()));
                self.sm.push(binding_name);
            }
            return;
        }

        // super() in constructor -- no opcode emission needed.
        // Constructor args are already on the stack.
        if func_name == "super" {
            self.sm.push(binding_name);
            return;
        }

        // checkMultiSig(sigs, pks) — special handling for OP_CHECKMULTISIG.
        if func_name == "checkMultiSig" && args.len() == 2 {
            self.lower_check_multi_sig(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "__array_access" {
            self.lower_array_access(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "reverseBytes" {
            self.lower_reverse_bytes(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "substr" {
            self.lower_substr(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "verifyRabinSig" {
            self.lower_verify_rabin_sig(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "verifyWOTS" {
            self.lower_verify_wots(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name.starts_with("verifySLHDSA_") {
            let param_key = func_name.trim_start_matches("verifySLHDSA_");
            self.lower_verify_slh_dsa(binding_name, param_key, args, binding_index, last_uses);
            return;
        }

        if func_name == "sha256Compress" {
            self.lower_sha256_compress(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "sha256Finalize" {
            self.lower_sha256_finalize(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "blake3Compress" {
            self.lower_blake3_compress(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "blake3Hash" {
            self.lower_blake3_hash(binding_name, args, binding_index, last_uses);
            return;
        }

        if is_ec_builtin(func_name) {
            self.lower_ec_builtin(binding_name, func_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "safediv" {
            self.lower_safediv(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "safemod" {
            self.lower_safemod(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "clamp" {
            self.lower_clamp(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "pow" {
            self.lower_pow(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "mulDiv" {
            self.lower_mul_div(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "percentOf" {
            self.lower_percent_of(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "sqrt" {
            self.lower_sqrt(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "gcd" {
            self.lower_gcd(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "divmod" {
            self.lower_divmod(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "log2" {
            self.lower_log2(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "sign" {
            self.lower_sign(binding_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "right" {
            self.lower_right(binding_name, args, binding_index, last_uses);
            return;
        }

        // pack and toByteString are no-ops: the value is already on the stack in
        // the correct representation. We just consume the arg and rename.
        if func_name == "pack" || func_name == "toByteString" {
            if !args.is_empty() {
                let is_last = self.is_last_use(&args[0], binding_index, last_uses);
                self.bring_to_top(&args[0], is_last);
                self.sm.pop();
            }
            self.sm.push(binding_name);
            return;
        }

        // computeStateOutputHash(preimage, stateBytes) — builds full BIP-143 output
        // serialization for single-output stateful continuation, then hashes it.
        if func_name == "computeStateOutputHash" {
            self.lower_compute_state_output_hash(binding_name, args, binding_index, last_uses);
            return;
        }

        // computeStateOutput(preimage, stateBytes) — same as computeStateOutputHash
        // but returns raw output bytes WITHOUT hashing. Used when the output bytes
        // need to be concatenated with a change output before hashing.
        if func_name == "computeStateOutput" {
            self.lower_compute_state_output(binding_name, args, binding_index, last_uses);
            return;
        }

        // buildChangeOutput(pkh, amount) — builds a P2PKH output serialization:
        //   amount(8LE) + varint(25) + OP_DUP OP_HASH160 OP_PUSHBYTES_20 <pkh> OP_EQUALVERIFY OP_CHECKSIG
        //   = amount(8LE) + 0x19 + 76a914 <pkh:20> 88ac
        if func_name == "buildChangeOutput" {
            self.lower_build_change_output(binding_name, args, binding_index, last_uses);
            return;
        }

        // Preimage field extractors — each needs a custom OP_SPLIT sequence
        // because OP_SPLIT produces two stack values and the intermediate stack
        // management cannot be expressed in the simple builtin_opcodes table.
        if func_name.starts_with("extract") {
            self.lower_extractor(binding_name, func_name, args, binding_index, last_uses);
            return;
        }

        // General builtin: push args in order, then emit opcodes
        for arg in args {
            let is_last = self.is_last_use(arg, binding_index, last_uses);
            self.bring_to_top(arg, is_last);
        }

        for _ in args {
            self.sm.pop();
        }

        if let Some(codes) = builtin_opcodes(func_name) {
            for code in codes {
                self.emit_op(StackOp::Opcode(code.to_string()));
            }
        } else {
            // Unknown function -- push a placeholder
            self.emit_op(StackOp::Push(PushValue::Int(0)));
            self.sm.push(binding_name);
            return;
        }

        if func_name == "split" {
            self.sm.push("");
            self.sm.push(binding_name);
        } else if func_name == "len" {
            self.sm.push("");
            self.sm.push(binding_name);
        } else {
            self.sm.push(binding_name);
        }

        self.track_depth();
    }

    fn lower_method_call(
        &mut self,
        binding_name: &str,
        object: &str,
        method: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // Consume the @this object reference — it's a compile-time concept,
        // not a runtime value. Without this, 0n stays on the stack.
        if self.sm.has(object) {
            self.bring_to_top(object, true);
            self.emit_op(StackOp::Drop);
            self.sm.pop();
        }

        if method == "getStateScript" {
            self.lower_get_state_script(binding_name);
            return;
        }

        // Check if this is a private method call that should be inlined
        if let Some(private_method) = self.private_methods.get(method).cloned() {
            self.inline_method_call(binding_name, &private_method, args, binding_index, last_uses);
            return;
        }

        // For other method calls, treat like a function call
        self.lower_call(binding_name, method, args, binding_index, last_uses);
    }

    /// Inline a private method by lowering its body in the current context.
    /// The method's parameters are bound to the call arguments.
    fn inline_method_call(
        &mut self,
        binding_name: &str,
        method: &ANFMethod,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // Track shadowed names so we can restore them after the body runs.
        // When a param name already exists on the stack, temporarily rename
        // the existing entry to avoid duplicate names which break Set-based
        // branch reconciliation in lower_if.
        let mut shadowed: Vec<(String, String)> = Vec::new();

        // Bind call arguments to private method params.
        for (i, arg) in args.iter().enumerate() {
            if i < method.params.len() {
                let is_last = self.is_last_use(arg, binding_index, last_uses);
                self.bring_to_top(arg, is_last);
                self.sm.pop();

                let param_name = &method.params[i].name;

                // If param_name already exists on the stack, shadow it by renaming
                // the existing entry to prevent duplicate-name issues.
                if self.sm.has(param_name) {
                    let existing_depth = self.sm.find_depth(param_name).unwrap();
                    let shadowed_name = format!("__shadowed_{}_{}", binding_index, param_name);
                    self.sm.rename_at_depth(existing_depth, &shadowed_name);
                    shadowed.push((param_name.clone(), shadowed_name));
                }

                // Rename to param name
                self.sm.push(param_name);
            }
        }

        // Lower the method body
        self.lower_bindings(&method.body, false);

        // Restore shadowed names so the caller's scope sees its original entries.
        for (param_name, shadowed_name) in &shadowed {
            if self.sm.has(shadowed_name) {
                let depth = self.sm.find_depth(shadowed_name).unwrap();
                self.sm.rename_at_depth(depth, param_name);
            }
        }

        // The last binding's result should be on top of the stack.
        // Rename it to the calling binding name.
        if !method.body.is_empty() {
            let last_binding_name = &method.body[method.body.len() - 1].name;
            if self.sm.depth() > 0 {
                let top_name = self.sm.peek_at_depth(0).to_string();
                if top_name == *last_binding_name {
                    self.sm.pop();
                    self.sm.push(binding_name);
                }
            }
        }
    }

    fn lower_if(
        &mut self,
        binding_name: &str,
        cond: &str,
        then_bindings: &[ANFBinding],
        else_bindings: &[ANFBinding],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
        terminal_assert: bool,
    ) {
        let is_last = self.is_last_use(cond, binding_index, last_uses);
        self.bring_to_top(cond, is_last);
        self.sm.pop(); // OP_IF consumes condition

        // Identify parent-scope items still needed after this if-expression.
        let mut protected_refs = HashSet::new();
        for (ref_name, &last_idx) in last_uses.iter() {
            if last_idx > binding_index && self.sm.has(ref_name) {
                protected_refs.insert(ref_name.clone());
            }
        }

        // Snapshot parent stackMap names before branches run
        let pre_if_names = self.sm.named_slots();

        // Lower then-branch
        let mut then_ctx = LoweringContext::new(&[], &self.properties);
        then_ctx.sm = self.sm.clone();
        then_ctx.outer_protected_refs = Some(protected_refs.clone());
        then_ctx.inside_branch = true;
        then_ctx.lower_bindings(then_bindings, terminal_assert);

        if terminal_assert && then_ctx.sm.depth() > 1 {
            let excess = then_ctx.sm.depth() - 1;
            for _ in 0..excess {
                then_ctx.emit_op(StackOp::Nip);
                then_ctx.sm.remove_at_depth(1);
            }
        }

        // Lower else-branch
        let mut else_ctx = LoweringContext::new(&[], &self.properties);
        else_ctx.sm = self.sm.clone();
        else_ctx.outer_protected_refs = Some(protected_refs);
        else_ctx.inside_branch = true;
        else_ctx.lower_bindings(else_bindings, terminal_assert);

        if terminal_assert && else_ctx.sm.depth() > 1 {
            let excess = else_ctx.sm.depth() - 1;
            for _ in 0..excess {
                else_ctx.emit_op(StackOp::Nip);
                else_ctx.sm.remove_at_depth(1);
            }
        }

        // Balance stack between branches so both end at the same depth.
        // When addOutput is inside an if-then with no else, the then-branch
        // consumes stack items and pushes a serialized output, while the
        // else-branch leaves the stack unchanged. Both must end at the same
        // depth for correct execution after OP_ENDIF.
        //
        // Fix: identify items consumed by the then-branch (present in parent
        // but gone after then). Emit targeted ROLL+DROP in the else-branch
        // to remove those same items, then push empty bytes as placeholder.
        // OP_CAT with empty bytes is identity (no-op for output hashing).
        // Identify items consumed asymmetrically between branches.
        // Phase 1: collect consumed names from both directions.
        let post_then_names = then_ctx.sm.named_slots();
        let mut consumed_names: Vec<String> = Vec::new();
        for name in &pre_if_names {
            if !post_then_names.contains(name) && else_ctx.sm.has(name) {
                consumed_names.push(name.clone());
            }
        }
        let post_else_names = else_ctx.sm.named_slots();
        let mut else_consumed_names: Vec<String> = Vec::new();
        for name in &pre_if_names {
            if !post_else_names.contains(name) && then_ctx.sm.has(name) {
                else_consumed_names.push(name.clone());
            }
        }

        // Phase 2: perform ALL drops before any placeholder pushes.
        // This prevents double-placeholder when bilateral drops balance each other.
        if !consumed_names.is_empty() {
            let mut depths: Vec<usize> = consumed_names
                .iter()
                .map(|n| else_ctx.sm.find_depth(n).unwrap())
                .collect();
            depths.sort_by(|a, b| b.cmp(a));
            for depth in depths {
                if depth == 0 {
                    else_ctx.emit_op(StackOp::Drop);
                    else_ctx.sm.pop();
                } else if depth == 1 {
                    else_ctx.emit_op(StackOp::Nip);
                    else_ctx.sm.remove_at_depth(1);
                } else {
                    else_ctx.emit_op(StackOp::Push(PushValue::Int(depth as i128)));
                    else_ctx.sm.push("");
                    else_ctx.emit_op(StackOp::Roll { depth });
                    else_ctx.sm.pop();
                    let rolled = else_ctx.sm.remove_at_depth(depth);
                    else_ctx.sm.push(&rolled);
                    else_ctx.emit_op(StackOp::Drop);
                    else_ctx.sm.pop();
                }
            }
        }
        if !else_consumed_names.is_empty() {
            let mut depths: Vec<usize> = else_consumed_names
                .iter()
                .map(|n| then_ctx.sm.find_depth(n).unwrap())
                .collect();
            depths.sort_by(|a, b| b.cmp(a));
            for depth in depths {
                if depth == 0 {
                    then_ctx.emit_op(StackOp::Drop);
                    then_ctx.sm.pop();
                } else if depth == 1 {
                    then_ctx.emit_op(StackOp::Nip);
                    then_ctx.sm.remove_at_depth(1);
                } else {
                    then_ctx.emit_op(StackOp::Push(PushValue::Int(depth as i128)));
                    then_ctx.sm.push("");
                    then_ctx.emit_op(StackOp::Roll { depth });
                    then_ctx.sm.pop();
                    let rolled = then_ctx.sm.remove_at_depth(depth);
                    then_ctx.sm.push(&rolled);
                    then_ctx.emit_op(StackOp::Drop);
                    then_ctx.sm.pop();
                }
            }
        }

        // Phase 3: single depth-balance check after ALL drops.
        // Push placeholder only if one branch is still deeper than the other.
        if then_ctx.sm.depth() > else_ctx.sm.depth() {
            // When the then-branch reassigned a local variable (if-without-else),
            // push a COPY of that variable in the else-branch instead of a generic
            // placeholder.
            let then_top_p3 = then_ctx.sm.peek_at_depth(0).to_string();
            if else_bindings.is_empty() && !then_top_p3.is_empty() && else_ctx.sm.has(&then_top_p3) {
                let var_depth = else_ctx.sm.find_depth(&then_top_p3).unwrap();
                if var_depth == 0 {
                    else_ctx.emit_op(StackOp::Dup);
                } else {
                    else_ctx.emit_op(StackOp::Push(PushValue::Int(var_depth as i128)));
                    else_ctx.sm.push("");
                    else_ctx.emit_op(StackOp::Pick { depth: var_depth });
                    else_ctx.sm.pop();
                }
                else_ctx.sm.push(&then_top_p3);
            } else {
                else_ctx.emit_op(StackOp::Push(PushValue::Bytes(Vec::new())));
                else_ctx.sm.push("");
            }
        } else if else_ctx.sm.depth() > then_ctx.sm.depth() {
            then_ctx.emit_op(StackOp::Push(PushValue::Bytes(Vec::new())));
            then_ctx.sm.push("");
        }

        let then_ops = then_ctx.ops;
        let else_ops = else_ctx.ops;

        self.emit_op(StackOp::If {
            then_ops,
            else_ops: if else_ops.is_empty() {
                Vec::new()
            } else {
                else_ops
            },
        });

        // Reconcile parent stackMap: remove items consumed by the branches.
        let post_branch_names = then_ctx.sm.named_slots();
        for name in &pre_if_names {
            if !post_branch_names.contains(name) && self.sm.has(name) {
                if let Some(depth) = self.sm.find_depth(name) {
                    self.sm.remove_at_depth(depth);
                }
            }
        }

        // The if expression may produce a result value on top.
        if then_ctx.sm.depth() > self.sm.depth() {
            let then_top = then_ctx.sm.peek_at_depth(0).to_string();
            let else_top = if else_ctx.sm.depth() > 0 {
                else_ctx.sm.peek_at_depth(0).to_string()
            } else {
                String::new()
            };
            let is_property = self.properties.iter().any(|p| p.name == then_top);
            if is_property && !then_top.is_empty() && then_top == else_top
                && then_top != binding_name && self.sm.has(&then_top)
            {
                // Both branches did update_prop for the same property
                self.sm.push(&then_top);
                for d in 1..self.sm.depth() {
                    if self.sm.peek_at_depth(d) == then_top {
                        if d == 1 {
                            self.emit_op(StackOp::Nip);
                            self.sm.remove_at_depth(1);
                        } else {
                            self.emit_op(StackOp::Push(PushValue::Int(d as i128)));
                            self.sm.push("");
                            self.emit_op(StackOp::Roll { depth: d + 1 });
                            self.sm.pop();
                            let rolled = self.sm.remove_at_depth(d);
                            self.sm.push(&rolled);
                            self.emit_op(StackOp::Drop);
                            self.sm.pop();
                        }
                        break;
                    }
                }
            } else if !then_top.is_empty() && !is_property && else_bindings.is_empty()
                && then_top != binding_name && self.sm.has(&then_top)
            {
                // If-without-else: then-branch reassigned a local variable that
                // was PICKed (outer-protected), leaving a stale copy on the stack.
                // Push the local name and remove the stale entry.
                self.sm.push(&then_top);
                for d in 1..self.sm.depth() {
                    if self.sm.peek_at_depth(d) == then_top {
                        if d == 1 {
                            self.emit_op(StackOp::Nip);
                            self.sm.remove_at_depth(1);
                        } else {
                            self.emit_op(StackOp::Push(PushValue::Int(d as i128)));
                            self.sm.push("");
                            self.emit_op(StackOp::Roll { depth: d + 1 });
                            self.sm.pop();
                            let rolled = self.sm.remove_at_depth(d);
                            self.sm.push(&rolled);
                            self.emit_op(StackOp::Drop);
                            self.sm.pop();
                        }
                        break;
                    }
                }
            } else {
                self.sm.push(binding_name);
            }
        } else if else_ctx.sm.depth() > self.sm.depth() {
            self.sm.push(binding_name);
        } else {
            // Void if — don't push phantom
        }
        self.track_depth();

        if then_ctx.max_depth > self.max_depth {
            self.max_depth = then_ctx.max_depth;
        }
        if else_ctx.max_depth > self.max_depth {
            self.max_depth = else_ctx.max_depth;
        }
    }

    fn lower_loop(
        &mut self,
        _binding_name: &str,
        count: usize,
        body: &[ANFBinding],
        iter_var: &str,
    ) {
        // Collect outer-scope names referenced in the loop body.
        // These must not be consumed in non-final iterations.
        let body_binding_names: HashSet<String> = body.iter().map(|b| b.name.clone()).collect();
        let mut outer_refs = HashSet::new();
        for b in body {
            if let ANFValue::LoadParam { name } = &b.value {
                if name != iter_var {
                    outer_refs.insert(name.clone());
                }
            }
            // Also protect @ref: targets from outer scope (not redefined in body)
            if let ANFValue::LoadConst { value: v } = &b.value {
                if let Some(s) = v.as_str() {
                    if s.len() > 5 && &s[..5] == "@ref:" {
                        let ref_name = &s[5..];
                        if !body_binding_names.contains(ref_name) {
                            outer_refs.insert(ref_name.to_string());
                        }
                    }
                }
            }
        }

        // Temporarily extend localBindings with body binding names so
        // @ref: to body-internal values can consume on last use.
        let prev_local_bindings = self.local_bindings.clone();
        self.local_bindings = self.local_bindings.union(&body_binding_names).cloned().collect();

        for i in 0..count {
            self.emit_op(StackOp::Push(PushValue::Int(i as i128)));
            self.sm.push(iter_var);

            let mut last_uses = compute_last_uses(body);

            // In non-final iterations, prevent outer-scope refs from being
            // consumed by setting their last-use beyond any body binding index.
            if i < count - 1 {
                for ref_name in &outer_refs {
                    last_uses.insert(ref_name.clone(), body.len());
                }
            }

            for (j, binding) in body.iter().enumerate() {
                self.lower_binding(binding, j, &last_uses);
            }

            // Clean up the iteration variable if it was not consumed by the body.
            // The body may not reference iter_var at all, leaving it on the stack.
            if self.sm.has(iter_var) {
                let depth = self.sm.find_depth(iter_var);
                if let Some(0) = depth {
                    self.emit_op(StackOp::Drop);
                    self.sm.pop();
                }
            }
        }
        // Restore localBindings
        self.local_bindings = prev_local_bindings;
        // Note: loops are statements, not expressions — they don't produce a
        // physical stack value. Do NOT push a dummy stackMap entry, as it would
        // desync the stackMap depth from the physical stack.
    }

    fn lower_assert(
        &mut self,
        value_ref: &str,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
        terminal: bool,
    ) {
        let is_last = self.is_last_use(value_ref, binding_index, last_uses);
        self.bring_to_top(value_ref, is_last);
        if terminal {
            // Terminal assert: leave value on stack for Bitcoin Script's
            // final truthiness check (no OP_VERIFY).
        } else {
            self.sm.pop();
            self.emit_op(StackOp::Opcode("OP_VERIFY".to_string()));
        }
        self.track_depth();
    }

    fn lower_update_prop(
        &mut self,
        prop_name: &str,
        value_ref: &str,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        let is_last = self.is_last_use(value_ref, binding_index, last_uses);
        self.bring_to_top(value_ref, is_last);
        self.sm.pop();
        self.sm.push(prop_name);

        // When NOT inside an if-branch, remove the old property entry from
        // the stack. After liftBranchUpdateProps transforms conditional
        // property updates into flat if-expressions + top-level update_prop,
        // the old value is dead and must be removed to keep stack depth correct.
        // Inside branches, the old value is kept for lower_if's same-property
        // detection to handle correctly.
        if !self.inside_branch {
            for d in 1..self.sm.depth() {
                if self.sm.peek_at_depth(d) == prop_name {
                    if d == 1 {
                        self.emit_op(StackOp::Nip);
                        self.sm.remove_at_depth(1);
                    } else {
                        self.emit_op(StackOp::Push(PushValue::Int(d as i128)));
                        self.sm.push("");
                        self.emit_op(StackOp::Roll { depth: d + 1 });
                        self.sm.pop();
                        let rolled = self.sm.remove_at_depth(d);
                        self.sm.push(&rolled);
                        self.emit_op(StackOp::Drop);
                        self.sm.pop();
                    }
                    break;
                }
            }
        }

        self.track_depth();
    }

    fn lower_get_state_script(&mut self, binding_name: &str) {
        let state_props: Vec<ANFProperty> = self
            .properties
            .iter()
            .filter(|p| !p.readonly)
            .cloned()
            .collect();

        if state_props.is_empty() {
            self.emit_op(StackOp::Push(PushValue::Bytes(Vec::new())));
            self.sm.push(binding_name);
            return;
        }

        let mut first = true;
        for prop in &state_props {
            if self.sm.has(&prop.name) {
                self.bring_to_top(&prop.name, true); // consume: raw value dead after serialization
            } else if let Some(ref val) = prop.initial_value {
                self.push_json_value(val);
                self.sm.push("");
            } else {
                self.emit_op(StackOp::Push(PushValue::Int(0)));
                self.sm.push("");
            }

            // Convert numeric/boolean values to fixed-width bytes via OP_NUM2BIN
            if prop.prop_type == "bigint" {
                self.emit_op(StackOp::Push(PushValue::Int(8)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_NUM2BIN".to_string()));
                self.sm.pop(); // pop the width
            } else if prop.prop_type == "boolean" {
                self.emit_op(StackOp::Push(PushValue::Int(1)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_NUM2BIN".to_string()));
                self.sm.pop(); // pop the width
            } else if prop.prop_type == "ByteString" {
                // Prepend push-data length prefix (matching SDK format)
                self.emit_push_data_encode();
            }
            // Other byte types (PubKey, Sig, Sha256, etc.) need no conversion

            if !first {
                self.sm.pop();
                self.sm.pop();
                self.emit_op(StackOp::Opcode("OP_CAT".to_string()));
                self.sm.push("");
            }
            first = false;
        }

        self.sm.pop();
        self.sm.push(binding_name);
        self.track_depth();
    }

    /// Builds the full BIP-143 output serialization for a single-output stateful
    /// continuation and hashes it with SHA256d. Uses _codePart implicit parameter
    /// for the code portion and extracts the amount from the preimage.
    fn lower_compute_state_output_hash(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &std::collections::HashMap<String, usize>,
    ) {
        let preimage_ref = &args[0];
        let state_bytes_ref = &args[1];

        // Bring stateBytes to stack first.
        let sb_last = self.is_last_use(state_bytes_ref, binding_index, last_uses);
        self.bring_to_top(state_bytes_ref, sb_last);

        // Extract amount from preimage for the continuation output.
        let pre_last = self.is_last_use(preimage_ref, binding_index, last_uses);
        self.bring_to_top(preimage_ref, pre_last);

        // Extract amount: last 52 bytes, take 8 bytes at offset 0.
        self.emit_op(StackOp::Opcode("OP_SIZE".into()));
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(52))); // 8 (amount) + 44 (tail)
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SUB".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".into())); // [prefix, amountAndTail]
        self.sm.pop();
        self.sm.pop();
        self.sm.push(""); // prefix
        self.sm.push(""); // amountAndTail
        self.emit_op(StackOp::Nip); // drop prefix
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(8)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".into())); // [amount(8), tail(44)]
        self.sm.pop();
        self.sm.pop();
        self.sm.push(""); // amount
        self.sm.push(""); // tail
        self.emit_op(StackOp::Drop); // drop tail
        self.sm.pop();
        // --- Stack: [..., stateBytes, amount(8LE)] ---

        // Save amount to altstack
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));
        self.sm.pop();

        // Bring _codePart to top (PICK — never consume, reused across outputs)
        self.bring_to_top("_codePart", false);
        // --- Stack: [..., stateBytes, codePart] ---

        // Append OP_RETURN + stateBytes
        self.emit_op(StackOp::Push(PushValue::Bytes(vec![0x6a])));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        // --- Stack: [..., stateBytes, codePart+OP_RETURN] ---

        self.emit_op(StackOp::Swap);
        self.sm.swap();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        // --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

        // Compute varint prefix for script length
        self.emit_op(StackOp::Opcode("OP_SIZE".into()));
        self.sm.push("");
        self.emit_varint_encoding();

        // Prepend varint to script
        self.emit_op(StackOp::Swap);
        self.sm.swap();
        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.push("");

        // Prepend amount from altstack
        self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));
        self.sm.push("");
        self.emit_op(StackOp::Swap);
        self.sm.swap();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");

        // Hash with SHA256d
        self.emit_op(StackOp::Opcode("OP_HASH256".into()));

        self.sm.pop();
        self.sm.push(binding_name);
        self.track_depth();
    }

    /// `computeStateOutput(preimage, stateBytes, newAmount)` — builds the continuation
    /// output using _newAmount and _codePart instead of extracting from preimage.
    /// Returns raw output bytes WITHOUT the final OP_HASH256.
    fn lower_compute_state_output(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &std::collections::HashMap<String, usize>,
    ) {
        let preimage_ref = &args[0];
        let state_bytes_ref = &args[1];
        let new_amount_ref = &args[2];

        // Consume preimage ref (no longer needed — we use _codePart and _newAmount).
        let pre_last = self.is_last_use(preimage_ref, binding_index, last_uses);
        self.bring_to_top(preimage_ref, pre_last);
        self.emit_op(StackOp::Drop);
        self.sm.pop();

        // Step 1: Convert _newAmount to 8-byte LE and save to altstack.
        let amount_last = self.is_last_use(new_amount_ref, binding_index, last_uses);
        self.bring_to_top(new_amount_ref, amount_last);
        self.emit_op(StackOp::Push(PushValue::Int(8)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));
        self.sm.pop();

        // Step 2: Bring stateBytes to stack.
        let sb_last = self.is_last_use(state_bytes_ref, binding_index, last_uses);
        self.bring_to_top(state_bytes_ref, sb_last);

        // Step 3: Bring _codePart to top (PICK — never consume, reused across outputs)
        self.bring_to_top("_codePart", false);
        // --- Stack: [..., stateBytes, codePart] ---

        // Step 4: Append OP_RETURN + stateBytes
        self.emit_op(StackOp::Push(PushValue::Bytes(vec![0x6a])));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        // --- Stack: [..., stateBytes, codePart+OP_RETURN] ---

        self.emit_op(StackOp::Swap);
        self.sm.swap();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        // --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

        // Step 5: Compute varint prefix for script length
        self.emit_op(StackOp::Opcode("OP_SIZE".into()));
        self.sm.push("");
        self.emit_varint_encoding();

        // Step 6: Prepend varint to script
        self.emit_op(StackOp::Swap);
        self.sm.swap();
        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.push("");

        // Step 7: Prepend _newAmount (8-byte LE) from altstack.
        self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));
        self.sm.push("");
        self.emit_op(StackOp::Swap);
        self.sm.swap();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        // --- Stack: [..., fullOutputSerialization] --- (NO hash)

        self.sm.pop();
        self.sm.push(binding_name);
        self.track_depth();
    }

    /// `buildChangeOutput(pkh, amount)` — builds a P2PKH output serialization:
    ///   amount(8LE) + 0x19 + 76a914 <pkh:20bytes> 88ac
    /// Total: 34 bytes (8 + 1 + 25).
    fn lower_build_change_output(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &std::collections::HashMap<String, usize>,
    ) {
        let pkh_ref = &args[0];
        let amount_ref = &args[1];

        // Step 1: Build the P2PKH locking script with length prefix.
        // Push prefix: varint(25) + OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 = 0x1976a914
        self.emit_op(StackOp::Push(PushValue::Bytes(vec![0x19, 0x76, 0xa9, 0x14])));
        self.sm.push("");

        // Push the 20-byte PKH
        let pkh_last = self.is_last_use(pkh_ref, binding_index, last_uses);
        self.bring_to_top(pkh_ref, pkh_last);
        // CAT: prefix || pkh
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");

        // Push suffix: OP_EQUALVERIFY + OP_CHECKSIG = 0x88ac
        self.emit_op(StackOp::Push(PushValue::Bytes(vec![0x88, 0xac])));
        self.sm.push("");
        // CAT: (prefix || pkh) || suffix
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        // --- Stack: [..., 0x1976a914{pkh}88ac] ---

        // Step 2: Prepend amount as 8-byte LE.
        let amount_last = self.is_last_use(amount_ref, binding_index, last_uses);
        self.bring_to_top(amount_ref, amount_last);
        self.emit_op(StackOp::Push(PushValue::Int(8)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".into()));
        self.sm.pop(); // pop width
        // Stack: [..., script, amount(8LE)]
        self.emit_op(StackOp::Swap);
        self.sm.swap();
        // Stack: [..., amount(8LE), script]
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        // --- Stack: [..., amount(8LE)+0x1976a914{pkh}88ac] ---

        self.sm.pop();
        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_add_output(
        &mut self,
        binding_name: &str,
        satoshis: &str,
        state_values: &[String],
        _preimage: &str,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // Build a full BIP-143 output serialization:
        //   amount(8LE) + varint(scriptLen) + codePart + OP_RETURN + stateBytes
        // Uses _codePart implicit parameter (passed by SDK) instead of extracting
        // codePart from the preimage. This is simpler and works with OP_CODESEPARATOR.

        let state_props: Vec<ANFProperty> = self
            .properties
            .iter()
            .filter(|p| !p.readonly)
            .cloned()
            .collect();

        // Step 1: Bring _codePart to top (PICK — never consume, reused across outputs)
        self.bring_to_top("_codePart", false);
        // --- Stack: [..., codePart] ---

        // Step 2: Append OP_RETURN byte (0x6a).
        self.emit_op(StackOp::Push(PushValue::Bytes(vec![0x6a])));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        // --- Stack: [..., codePart+OP_RETURN] ---

        // Step 3: Serialize each state value and concatenate.
        for (i, value_ref) in state_values.iter().enumerate() {
            if i >= state_props.len() {
                break;
            }
            let prop = &state_props[i];

            let is_last = self.is_last_use(value_ref, binding_index, last_uses);
            self.bring_to_top(value_ref, is_last);

            if prop.prop_type == "bigint" {
                self.emit_op(StackOp::Push(PushValue::Int(8)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_NUM2BIN".to_string()));
                self.sm.pop();
            } else if prop.prop_type == "boolean" {
                self.emit_op(StackOp::Push(PushValue::Int(1)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_NUM2BIN".to_string()));
                self.sm.pop();
            } else if prop.prop_type == "ByteString" {
                // Prepend push-data length prefix (matching SDK format)
                self.emit_push_data_encode();
            }

            self.sm.pop();
            self.sm.pop();
            self.emit_op(StackOp::Opcode("OP_CAT".to_string()));
            self.sm.push("");
        }
        // --- Stack: [..., codePart+OP_RETURN+stateBytes] ---

        // Step 4: Compute varint prefix for the full script length.
        self.emit_op(StackOp::Opcode("OP_SIZE".into())); // [script, len]
        self.sm.push("");
        self.emit_varint_encoding();
        // --- Stack: [..., script, varint] ---

        // Step 5: Prepend varint to script: SWAP CAT
        self.emit_op(StackOp::Swap);
        self.sm.swap();
        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
        self.sm.push("");
        // --- Stack: [..., varint+script] ---

        // Step 6: Prepend satoshis as 8-byte LE.
        let is_last_satoshis = self.is_last_use(satoshis, binding_index, last_uses);
        self.bring_to_top(satoshis, is_last_satoshis);
        self.emit_op(StackOp::Push(PushValue::Int(8)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".to_string()));
        self.sm.pop(); // pop the width
        // Stack: [..., varint+script, satoshis(8LE)]
        self.emit_op(StackOp::Swap);
        self.sm.swap();
        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".to_string())); // satoshis || varint+script
        self.sm.push("");
        // --- Stack: [..., amount(8LE)+varint+scriptPubKey] ---

        // Rename top to binding name
        self.sm.pop();
        self.sm.push(binding_name);
        self.track_depth();
    }

    /// `add_raw_output(satoshis, scriptBytes)` — builds a raw output serialization:
    ///   amount(8LE) + varint(scriptLen) + scriptBytes
    /// The scriptBytes are used as-is (no codePart/state insertion).
    fn lower_add_raw_output(
        &mut self,
        binding_name: &str,
        satoshis: &str,
        script_bytes: &str,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // Step 1: Bring scriptBytes to top
        let script_is_last = self.is_last_use(script_bytes, binding_index, last_uses);
        self.bring_to_top(script_bytes, script_is_last);

        // Step 2: Compute varint prefix for script length
        self.emit_op(StackOp::Opcode("OP_SIZE".to_string())); // [script, len]
        self.sm.push("");
        self.emit_varint_encoding();
        // --- Stack: [..., script, varint] ---

        // Step 3: Prepend varint to script: SWAP CAT
        self.emit_op(StackOp::Swap); // [varint, script]
        self.sm.swap();
        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".to_string())); // [varint+script]
        self.sm.push("");

        // Step 4: Prepend satoshis as 8-byte LE
        let sat_is_last = self.is_last_use(satoshis, binding_index, last_uses);
        self.bring_to_top(satoshis, sat_is_last);
        self.emit_op(StackOp::Push(PushValue::Int(8)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".to_string()));
        self.sm.pop(); // pop width
        // Stack: [..., varint+script, satoshis(8LE)]
        self.emit_op(StackOp::Swap);
        self.sm.swap();
        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_CAT".to_string())); // satoshis || varint+script
        self.sm.push("");

        // Rename top to binding name
        self.sm.pop();
        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_array_literal(
        &mut self,
        binding_name: &str,
        elements: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // An array_literal brings each element to the top of the stack.
        // The elements remain as individual stack entries; the binding name tracks
        // the last element so that callers (e.g. checkMultiSig) can find them.
        for elem in elements {
            let is_last = self.is_last_use(elem, binding_index, last_uses);
            self.bring_to_top(elem, is_last);
            self.sm.pop();
            self.sm.push(""); // anonymous stack entry for intermediate elements
        }
        // Rename the topmost entry to the binding name
        if !elements.is_empty() {
            self.sm.pop();
        }
        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_check_multi_sig(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // checkMultiSig(sigs, pks) — emits the OP_CHECKMULTISIG sequence.
        // Bitcoin Script stack layout:
        //   OP_0 <sig1> ... <sigN> <nSigs> <pk1> ... <pkM> <nPKs> OP_CHECKMULTISIG
        //
        // The two args reference array_literal bindings whose individual elements
        // are already on the stack.

        // Push OP_0 dummy (Bitcoin CHECKMULTISIG off-by-one bug workaround)
        self.emit_op(StackOp::Push(PushValue::Int(0)));
        self.sm.push("");

        // Bring sigs array ref to top
        let sigs_is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], sigs_is_last);

        // Bring pks array ref to top
        let pks_is_last = self.is_last_use(&args[1], binding_index, last_uses);
        self.bring_to_top(&args[1], pks_is_last);

        // Pop all args + dummy
        self.sm.pop(); // pks
        self.sm.pop(); // sigs
        self.sm.pop(); // OP_0 dummy

        self.emit_op(StackOp::Opcode("OP_CHECKMULTISIG".to_string()));
        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_check_preimage(
        &mut self,
        binding_name: &str,
        preimage: &str,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // OP_PUSH_TX: verify the sighash preimage matches the current spending
        // transaction.  See https://wiki.bitcoinsv.io/index.php/OP_PUSH_TX
        //
        // The technique uses a well-known ECDSA keypair where private key = 1
        // (so the public key is the secp256k1 generator point G, compressed:
        //   0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798).
        //
        // At spending time the SDK must:
        //   1. Serialise the BIP-143 sighash preimage for the current input.
        //   2. Compute sighash = SHA256(SHA256(preimage)).
        //   3. Derive an ECDSA signature (r, s) with privkey = 1:
        //        r = Gx  (x-coordinate of the generator point, constant)
        //        s = (sighash + r) mod n
        //   4. DER-encode (r, s) and append the SIGHASH_ALL|FORKID byte (0x41).
        //   5. Push <sig> <preimage> (plus any other method args) as the
        //      unlocking script.
        //
        // The locking script sequence:
        //   [bring preimage to top]     -- via PICK or ROLL
        //   [bring _opPushTxSig to top] -- via ROLL (consuming)
        //   <G>                         -- push compressed generator point
        //   OP_CHECKSIG                 -- verify sig over SHA256(SHA256(preimage))
        //   OP_VERIFY                   -- abort if invalid
        //   -- preimage remains on stack for field extractors
        //
        // Stack map trace:
        //   After bring_to_top(preimage):  [..., preimage]
        //   After bring_to_top(sig, true): [..., preimage, _opPushTxSig]
        //   After push G:                  [..., preimage, _opPushTxSig, null(G)]
        //   After OP_CHECKSIG:             [..., preimage, null(result)]
        //   After OP_VERIFY:               [..., preimage]

        // Step 0: Emit OP_CODESEPARATOR so that the scriptCode in the BIP-143
        // preimage is only the code after this point. This reduces preimage size
        // for large scripts and is required for scripts > ~32KB.
        self.emit_op(StackOp::Opcode("OP_CODESEPARATOR".to_string()));

        // Step 1: Bring preimage to top.
        let is_last = self.is_last_use(preimage, binding_index, last_uses);
        self.bring_to_top(preimage, is_last);

        // Step 2: Bring the implicit _opPushTxSig to top (consuming).
        self.bring_to_top("_opPushTxSig", true);

        // Step 3: Push compressed secp256k1 generator point G (33 bytes).
        let g: Vec<u8> = vec![
            0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
            0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
            0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
            0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
            0x98,
        ];
        self.emit_op(StackOp::Push(PushValue::Bytes(g)));
        self.sm.push(""); // G on stack

        // Step 4: OP_CHECKSIG -- pops pubkey (G) and sig, pushes boolean result.
        self.emit_op(StackOp::Opcode("OP_CHECKSIG".to_string()));
        self.sm.pop(); // G consumed
        self.sm.pop(); // _opPushTxSig consumed
        self.sm.push(""); // boolean result

        // Step 5: OP_VERIFY -- abort if false, removes result from stack.
        self.emit_op(StackOp::Opcode("OP_VERIFY".to_string()));
        self.sm.pop(); // result consumed

        // The preimage is now on top (from Step 1). Rename to binding name
        // so field extractors can reference it.
        self.sm.pop();
        self.sm.push(binding_name);

        self.track_depth();
    }

    /// Lower `deserialize_state(preimage)` — extracts mutable property values
    /// from the BIP-143 preimage's scriptCode field. The state is stored as the
    /// last `stateLen` bytes of the scriptCode (after OP_RETURN).
    ///
    /// For each mutable property, the value is extracted, converted to the
    /// correct type (BIN2NUM for bigint/boolean), and pushed onto the stack
    /// with the property name in the stackMap. This allows `load_prop` to
    /// find the deserialized values instead of using hardcoded initial values.
    fn lower_deserialize_state(
        &mut self,
        preimage_ref: &str,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        let mut prop_names: Vec<String> = Vec::new();
        let mut prop_types: Vec<String> = Vec::new();
        let mut prop_sizes: Vec<i128> = Vec::new();
        let mut has_variable_length = false;

        for p in &self.properties {
            if p.readonly {
                continue;
            }
            prop_names.push(p.name.clone());
            prop_types.push(p.prop_type.clone());
            let sz: i128 = match p.prop_type.as_str() {
                "bigint" => 8,
                "boolean" => 1,
                "PubKey" => 33,
                "Addr" => 20,
                "Sha256" => 32,
                "Point" => 64,
                "ByteString" => { has_variable_length = true; -1 },
                _ => panic!("deserialize_state: unsupported type: {}", p.prop_type),
            };
            prop_sizes.push(sz);
        }

        if prop_names.is_empty() {
            return;
        }

        let is_last = self.is_last_use(preimage_ref, binding_index, last_uses);
        self.bring_to_top(preimage_ref, is_last);

        // 1. Skip first 104 bytes (header), drop prefix.
        self.emit_op(StackOp::Push(PushValue::Int(104)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");
        self.emit_op(StackOp::Nip);
        self.sm.pop(); self.sm.pop();
        self.sm.push("");

        // 2. Drop tail 44 bytes.
        self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(44)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SUB".to_string()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");
        self.emit_op(StackOp::Drop);
        self.sm.pop();

        // 3. Drop amount (last 8 bytes).
        self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(8)));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SUB".to_string()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");
        self.emit_op(StackOp::Drop);
        self.sm.pop();

        if !has_variable_length {
            let state_len: i128 = prop_sizes.iter().sum();

            // 4. Extract last stateLen bytes.
            self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));
            self.sm.push("");
            self.emit_op(StackOp::Push(PushValue::Int(state_len)));
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_SUB".to_string()));
            self.sm.pop(); self.sm.pop();
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
            self.sm.pop(); self.sm.pop();
            self.sm.push(""); self.sm.push("");
            self.emit_op(StackOp::Nip);
            self.sm.pop(); self.sm.pop();
            self.sm.push("");

            // 5. Split fixed-size state fields.
            self.split_fixed_state_fields(&prop_names, &prop_types, &prop_sizes);
        } else if !self.sm.has("_codePart") {
            // Variable-length state but _codePart not available (terminal method).
            self.emit_op(StackOp::Drop);
            self.sm.pop();
        } else {
            // Variable-length path: strip varint, use _codePart to find state
            self.emit_op(StackOp::Push(PushValue::Int(1)));
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
            self.sm.pop(); self.sm.pop();
            self.sm.push(""); self.sm.push("");
            self.emit_op(StackOp::Swap);
            self.sm.swap();
            self.emit_op(StackOp::Dup);
            self.sm.push("");
            // Zero-pad before BIN2NUM to prevent sign-bit misinterpretation (0xfd → -125 without pad)
            self.emit_op(StackOp::Push(PushValue::Bytes(vec![0])));
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_CAT".into()));
            self.sm.pop(); self.sm.pop();
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
            self.emit_op(StackOp::Push(PushValue::Int(253)));
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_LESSTHAN".into()));
            self.sm.pop(); self.sm.pop();
            self.sm.push("");

            self.emit_op(StackOp::Opcode("OP_IF".into()));
            self.sm.pop();
            let sm_at_varint_if = self.sm.clone();
            self.emit_op(StackOp::Drop);
            self.sm.pop();

            self.emit_op(StackOp::Opcode("OP_ELSE".into()));
            self.sm = sm_at_varint_if.clone();
            self.emit_op(StackOp::Drop);
            self.sm.pop();
            self.emit_op(StackOp::Push(PushValue::Int(2)));
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
            self.sm.pop(); self.sm.pop();
            self.sm.push(""); self.sm.push("");
            self.emit_op(StackOp::Nip);
            self.sm.pop(); self.sm.pop();
            self.sm.push("");

            self.emit_op(StackOp::Opcode("OP_ENDIF".into()));

            // Compute skip = SIZE(_codePart) - codeSepIdx
            self.bring_to_top("_codePart", false);
            self.emit_op(StackOp::Opcode("OP_SIZE".into()));
            self.sm.push("");
            self.emit_op(StackOp::Nip);
            self.sm.pop(); self.sm.pop();
            self.sm.push("");
            self.emit_op(StackOp::PushCodeSepIndex);
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_SUB".into()));
            self.sm.pop(); self.sm.pop();
            self.sm.push("");

            // Split scriptCode at skip to get state
            self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
            self.sm.pop(); self.sm.pop();
            self.sm.push(""); self.sm.push("");
            self.emit_op(StackOp::Nip);
            self.sm.pop(); self.sm.pop();
            self.sm.push("");

            // Parse variable-length state fields
            self.parse_variable_length_state_fields(&prop_names, &prop_types, &prop_sizes);
        }

        self.track_depth();
    }

    fn split_fixed_state_fields(
        &mut self,
        prop_names: &[String],
        prop_types: &[String],
        prop_sizes: &[i128],
    ) {
        let num_props = prop_names.len();
        if num_props == 1 {
            if prop_types[0] == "bigint" || prop_types[0] == "boolean" {
                self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
            }
            self.sm.pop();
            self.sm.push(&prop_names[0]);
        } else {
            for i in 0..num_props {
                let sz = prop_sizes[i];
                if i < num_props - 1 {
                    self.emit_op(StackOp::Push(PushValue::Int(sz)));
                    self.sm.push("");
                    self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                    self.sm.pop(); self.sm.pop();
                    self.sm.push(""); self.sm.push("");
                    self.emit_op(StackOp::Swap);
                    self.sm.swap();
                    if prop_types[i] == "bigint" || prop_types[i] == "boolean" {
                        self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
                    }
                    self.emit_op(StackOp::Swap);
                    self.sm.swap();
                    self.sm.pop(); self.sm.pop();
                    self.sm.push(&prop_names[i]);
                    self.sm.push("");
                } else {
                    if prop_types[i] == "bigint" || prop_types[i] == "boolean" {
                        self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
                    }
                    self.sm.pop();
                    self.sm.push(&prop_names[i]);
                }
            }
        }
    }

    fn parse_variable_length_state_fields(
        &mut self,
        prop_names: &[String],
        prop_types: &[String],
        prop_sizes: &[i128],
    ) {
        let num_props = prop_names.len();
        if num_props == 1 {
            if prop_types[0] == "ByteString" {
                // Single ByteString field: decode push-data prefix, drop trailing empty
                self.emit_push_data_decode(); // [..., data, remaining]
                self.emit_op(StackOp::Drop); self.sm.pop();
            } else if prop_types[0] == "bigint" || prop_types[0] == "boolean" {
                self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
            }
            self.sm.pop();
            self.sm.push(&prop_names[0]);
        } else {
            for i in 0..num_props {
                if i < num_props - 1 {
                    if prop_types[i] == "ByteString" {
                        // ByteString: decode push-data prefix, extract data
                        self.emit_push_data_decode(); // [..., data, rest]
                        self.sm.pop(); self.sm.pop();
                        self.sm.push(&prop_names[i]);
                        self.sm.push(""); // rest on top
                    } else {
                        self.emit_op(StackOp::Push(PushValue::Int(prop_sizes[i])));
                        self.sm.push("");
                        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
                        self.sm.pop(); self.sm.pop();
                        self.sm.push(""); self.sm.push("");
                        self.emit_op(StackOp::Swap); self.sm.swap();
                        if prop_types[i] == "bigint" || prop_types[i] == "boolean" {
                            self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
                        }
                        self.emit_op(StackOp::Swap); self.sm.swap();
                        self.sm.pop(); self.sm.pop();
                        self.sm.push(&prop_names[i]);
                        self.sm.push("");
                    }
                } else {
                    if prop_types[i] == "ByteString" {
                        // Last ByteString: decode push-data prefix, drop trailing empty
                        self.emit_push_data_decode(); // [..., data, remaining]
                        self.emit_op(StackOp::Drop); self.sm.pop();
                    } else if prop_types[i] == "bigint" || prop_types[i] == "boolean" {
                        self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
                    }
                    self.sm.pop();
                    self.sm.push(&prop_names[i]);
                }
            }
        }
    }

    /// Lower a preimage field extractor call.
    ///
    /// The SigHashPreimage follows BIP-143 format:
    ///   Offset  Bytes  Field
    ///   0       4      nVersion (LE uint32)
    ///   4       32     hashPrevouts
    ///   36      32     hashSequence
    ///   68      36     outpoint (txid 32 + vout 4)
    ///   104     var    scriptCode (varint-prefixed)
    ///   var     8      amount (satoshis, LE int64)
    ///   var     4      nSequence
    ///   var     32     hashOutputs
    ///   var     4      nLocktime
    ///   var     4      sighashType
    ///
    /// Fixed-offset fields use absolute OP_SPLIT positions.
    /// Variable-offset fields use end-relative positions via OP_SIZE.
    fn lower_extractor(
        &mut self,
        binding_name: &str,
        func_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(!args.is_empty(), "{} requires 1 argument", func_name);
        let is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], is_last);

        // The preimage is now on top of the stack.
        self.sm.pop(); // consume the preimage from stack map

        match func_name {
            "extractVersion" => {
                // <preimage> 4 OP_SPLIT OP_DROP OP_BIN2NUM
                self.emit_op(StackOp::Push(PushValue::Int(4)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Drop);
                self.sm.pop();
                self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
            }
            "extractHashPrevouts" => {
                // <preimage> 4 OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP
                self.emit_op(StackOp::Push(PushValue::Int(4)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(32)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop(); // pop position (32)
                self.sm.pop(); // pop data being split
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Drop);
                self.sm.pop();
            }
            "extractHashSequence" => {
                // <preimage> 36 OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP
                self.emit_op(StackOp::Push(PushValue::Int(36)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(32)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop(); // pop position (32)
                self.sm.pop(); // pop data being split
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Drop);
                self.sm.pop();
            }
            "extractOutpoint" => {
                // <preimage> 68 OP_SPLIT OP_NIP 36 OP_SPLIT OP_DROP
                self.emit_op(StackOp::Push(PushValue::Int(68)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(36)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop(); // pop position (36)
                self.sm.pop(); // pop data being split
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Drop);
                self.sm.pop();
            }
            "extractSigHashType" => {
                // End-relative: last 4 bytes, converted to number.
                // <preimage> OP_SIZE 4 OP_SUB OP_SPLIT OP_NIP OP_BIN2NUM
                self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(4)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SUB".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
            }
            "extractLocktime" => {
                // End-relative: 4 bytes before the last 4 (sighashType).
                // <preimage> OP_SIZE 8 OP_SUB OP_SPLIT OP_NIP 4 OP_SPLIT OP_DROP OP_BIN2NUM
                self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(8)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SUB".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(4)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop(); // pop position (4)
                self.sm.pop(); // pop value being split
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Drop);
                self.sm.pop();
                self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
            }
            "extractOutputHash" | "extractOutputs" => {
                // End-relative: 32 bytes before the last 8 (nLocktime 4 + sighashType 4).
                // <preimage> OP_SIZE 40 OP_SUB OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP
                self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(40)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SUB".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(32)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop(); // pop position (32)
                self.sm.pop(); // pop value being split (last40)
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Drop);
                self.sm.pop();
            }
            "extractAmount" => {
                // End-relative: 8 bytes at offset -(52) from end.
                // <preimage> OP_SIZE 52 OP_SUB OP_SPLIT OP_NIP 8 OP_SPLIT OP_DROP OP_BIN2NUM
                self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(52)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SUB".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(8)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop(); // pop position (8)
                self.sm.pop(); // pop value being split
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Drop);
                self.sm.pop();
                self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
            }
            "extractSequence" => {
                // End-relative: 4 bytes (nSequence) at offset -(44) from end.
                // <preimage> OP_SIZE 44 OP_SUB OP_SPLIT OP_NIP 4 OP_SPLIT OP_DROP OP_BIN2NUM
                self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(44)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SUB".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(4)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop(); // pop position (4)
                self.sm.pop(); // pop value being split
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Drop);
                self.sm.pop();
                self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
            }
            "extractScriptCode" => {
                // Variable-length field at offset 104. End-relative tail = 52 bytes.
                // <preimage> 104 OP_SPLIT OP_NIP OP_SIZE 52 OP_SUB OP_SPLIT OP_DROP
                self.emit_op(StackOp::Push(PushValue::Int(104)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(52)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SUB".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Drop);
                self.sm.pop();
            }
            "extractInputIndex" => {
                // Input index = vout field of outpoint, at offset 100, 4 bytes.
                // <preimage> 100 OP_SPLIT OP_NIP 4 OP_SPLIT OP_DROP OP_BIN2NUM
                self.emit_op(StackOp::Push(PushValue::Int(100)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(4)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop(); // pop position (4)
                self.sm.pop(); // pop value being split
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Drop);
                self.sm.pop();
                self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
            }
            _ => panic!("unknown extractor: {}", func_name),
        }

        // Rename top of stack to the binding name
        self.sm.pop();
        self.sm.push(binding_name);
        self.track_depth();
    }

    /// Lower `__array_access(data, index)` — ByteString byte-level indexing.
    ///
    /// Compiled to:
    ///   `<data> <index> OP_SPLIT OP_NIP 1 OP_SPLIT OP_DROP OP_BIN2NUM`
    ///
    /// Stack trace:
    ///   `[..., data, index]`
    ///   `OP_SPLIT  → [..., left, right]`       (split at index)
    ///   `OP_NIP    → [..., right]`             (discard left)
    ///   `push 1    → [..., right, 1]`
    ///   `OP_SPLIT  → [..., firstByte, rest]`   (split off first byte)
    ///   `OP_DROP   → [..., firstByte]`         (discard rest)
    ///   `OP_BIN2NUM → [..., numericValue]`     (convert byte to bigint)
    fn lower_array_access(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 2, "__array_access requires 2 arguments (object, index)");

        let obj = &args[0];
        let index = &args[1];

        // Push the data (ByteString) onto the stack
        let obj_is_last = self.is_last_use(obj, binding_index, last_uses);
        self.bring_to_top(obj, obj_is_last);

        // Push the index onto the stack
        let index_is_last = self.is_last_use(index, binding_index, last_uses);
        self.bring_to_top(index, index_is_last);

        // OP_SPLIT at index: stack = [..., left, right]
        self.sm.pop();  // index consumed
        self.sm.pop();  // data consumed
        self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
        self.sm.push("");  // left part (discard)
        self.sm.push("");  // right part (keep)

        // OP_NIP: discard left, keep right: stack = [..., right]
        self.emit_op(StackOp::Nip);
        self.sm.pop();
        let right_part = self.sm.pop();
        self.sm.push(&right_part);

        // Push 1 for the next split (extract 1 byte)
        self.emit_op(StackOp::Push(PushValue::Int(1)));
        self.sm.push("");

        // OP_SPLIT: split off first byte: stack = [..., firstByte, rest]
        self.sm.pop();  // 1 consumed
        self.sm.pop();  // right consumed
        self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
        self.sm.push("");  // first byte (keep)
        self.sm.push("");  // rest (discard)

        // OP_DROP: discard rest: stack = [..., firstByte]
        self.emit_op(StackOp::Drop);
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");

        // OP_BIN2NUM: convert single byte to numeric value
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));

        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_reverse_bytes(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(!args.is_empty(), "reverseBytes requires 1 argument");
        let is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], is_last);

        // Variable-length byte reversal using bounded unrolled loop.
        // Each iteration peels off the first byte and prepends it to the result.
        // 520 iterations covers the maximum BSV element size.
        self.sm.pop();

        // Push empty result (OP_0), swap so data is on top
        self.emit_op(StackOp::Push(PushValue::Int(0)));
        self.emit_op(StackOp::Swap);

        // 520 iterations (max BSV element size)
        for _ in 0..520 {
            // Stack: [result, data]
            self.emit_op(StackOp::Opcode("OP_DUP".to_string()));
            self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));
            self.emit_op(StackOp::Nip);
            self.emit_op(StackOp::If {
                then_ops: vec![
                    StackOp::Push(PushValue::Int(1)),
                    StackOp::Opcode("OP_SPLIT".to_string()),
                    StackOp::Swap,
                    StackOp::Rot,
                    StackOp::Opcode("OP_CAT".to_string()),
                    StackOp::Swap,
                ],
                else_ops: vec![],
            });
        }

        // Drop empty remainder
        self.emit_op(StackOp::Drop);

        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_substr(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 3, "substr requires 3 arguments");

        let data = &args[0];
        let start = &args[1];
        let length = &args[2];

        let data_is_last = self.is_last_use(data, binding_index, last_uses);
        self.bring_to_top(data, data_is_last);

        let start_is_last = self.is_last_use(start, binding_index, last_uses);
        self.bring_to_top(start, start_is_last);

        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
        self.sm.push("");
        self.sm.push("");

        self.emit_op(StackOp::Nip);
        self.sm.pop();
        let right_part = self.sm.pop();
        self.sm.push(&right_part);

        let len_is_last = self.is_last_use(length, binding_index, last_uses);
        self.bring_to_top(length, len_is_last);

        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
        self.sm.push("");
        self.sm.push("");

        self.emit_op(StackOp::Drop);
        self.sm.pop();
        self.sm.pop();

        self.sm.push(binding_name);
        self.track_depth();
    }
    fn lower_verify_rabin_sig(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 4, "verifyRabinSig requires 4 arguments");

        // Stack input: <msg> <sig> <padding> <pubKey>
        // Computation: (sig^2 + padding) mod pubKey == SHA256(msg)
        // Opcode sequence: OP_SWAP OP_ROT OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
        let msg = &args[0];
        let sig = &args[1];
        let padding = &args[2];
        let pub_key = &args[3];

        let msg_is_last = self.is_last_use(msg, binding_index, last_uses);
        self.bring_to_top(msg, msg_is_last);

        let sig_is_last = self.is_last_use(sig, binding_index, last_uses);
        self.bring_to_top(sig, sig_is_last);

        let padding_is_last = self.is_last_use(padding, binding_index, last_uses);
        self.bring_to_top(padding, padding_is_last);

        let pub_key_is_last = self.is_last_use(pub_key, binding_index, last_uses);
        self.bring_to_top(pub_key, pub_key_is_last);

        // Pop all 4 args from stack map
        self.sm.pop();
        self.sm.pop();
        self.sm.pop();
        self.sm.pop();

        // Emit the Rabin signature verification opcode sequence
        // Stack: msg(3) sig(2) padding(1) pubKey(0)
        self.emit_op(StackOp::Opcode("OP_SWAP".to_string()));  // msg sig pubKey padding
        self.emit_op(StackOp::Opcode("OP_ROT".to_string()));   // msg pubKey padding sig
        self.emit_op(StackOp::Opcode("OP_DUP".to_string()));
        self.emit_op(StackOp::Opcode("OP_MUL".to_string()));   // msg pubKey padding sig^2
        self.emit_op(StackOp::Opcode("OP_ADD".to_string()));   // msg pubKey (sig^2+padding)
        self.emit_op(StackOp::Opcode("OP_SWAP".to_string()));  // msg (sig^2+padding) pubKey
        self.emit_op(StackOp::Opcode("OP_MOD".to_string()));   // msg ((sig^2+padding) mod pubKey)
        self.emit_op(StackOp::Opcode("OP_SWAP".to_string()));  // ((sig^2+padding) mod pubKey) msg
        self.emit_op(StackOp::Opcode("OP_SHA256".to_string()));
        self.emit_op(StackOp::Opcode("OP_EQUAL".to_string()));

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// Lower sign(x) to Script that avoids division by zero for x == 0.
    /// OP_DUP OP_IF OP_DUP OP_ABS OP_SWAP OP_DIV OP_ENDIF
    fn lower_sign(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(!args.is_empty(), "sign requires 1 argument");
        let x = &args[0];

        let x_is_last = self.is_last_use(x, binding_index, last_uses);
        self.bring_to_top(x, x_is_last);
        self.sm.pop();

        self.emit_op(StackOp::Opcode("OP_DUP".to_string()));
        self.emit_op(StackOp::If {
            then_ops: vec![
                StackOp::Opcode("OP_DUP".to_string()),
                StackOp::Opcode("OP_ABS".to_string()),
                StackOp::Swap,
                StackOp::Opcode("OP_DIV".to_string()),
            ],
            else_ops: vec![],
        });

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// Lower right(data, len) to Script.
    /// OP_SWAP OP_SIZE OP_ROT OP_SUB OP_SPLIT OP_NIP
    fn lower_right(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 2, "right requires 2 arguments");
        let data = &args[0];
        let length = &args[1];

        let data_is_last = self.is_last_use(data, binding_index, last_uses);
        self.bring_to_top(data, data_is_last);

        let length_is_last = self.is_last_use(length, binding_index, last_uses);
        self.bring_to_top(length, length_is_last);

        self.sm.pop(); // len
        self.sm.pop(); // data

        self.emit_op(StackOp::Swap);                                     // <len> <data>
        self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));            // <len> <data> <size>
        self.emit_op(StackOp::Rot);                                      // <data> <size> <len>
        self.emit_op(StackOp::Opcode("OP_SUB".to_string()));             // <data> <size-len>
        self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));           // <left> <right>
        self.emit_op(StackOp::Nip);                                      // <right>

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// Emit one WOTS+ chain with RFC 8391 tweakable hash.
    /// Stack entry: pubSeed(bottom) sig csum endpt digit(top)
    /// Stack exit:  pubSeed(bottom) sigRest newCsum newEndpt
    fn emit_wots_one_chain(&mut self, chain_index: usize) {
        // Save steps_copy = 15 - digit to alt (for checksum accumulation later)
        self.emit_op(StackOp::Opcode("OP_DUP".into()));
        self.emit_op(StackOp::Push(PushValue::Int(15)));
        self.emit_op(StackOp::Swap);
        self.emit_op(StackOp::Opcode("OP_SUB".into()));
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into())); // push#1: steps_copy

        // Save endpt, csum to alt. Leave pubSeed+sig+digit on main.
        self.emit_op(StackOp::Swap);
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into())); // push#2: endpt
        self.emit_op(StackOp::Swap);
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into())); // push#3: csum
        // main: pubSeed sig digit

        // Split 32B sig element
        self.emit_op(StackOp::Swap);
        self.emit_op(StackOp::Push(PushValue::Int(32)));
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into())); // push#4: sigRest
        self.emit_op(StackOp::Swap);
        // main: pubSeed sigElem digit

        // Hash loop: skip first `digit` iterations, then apply F for the rest.
        // When digit > 0: decrement (skip). When digit == 0: hash at step j.
        // Stack: pubSeed(depth2) sigElem(depth1) digit(depth0=top)
        for j in 0..15usize {
            let adrs_bytes = vec![chain_index as u8, j as u8];
            self.emit_op(StackOp::Opcode("OP_DUP".into()));
            self.emit_op(StackOp::Opcode("OP_0NOTEQUAL".into()));
            self.emit_op(StackOp::If {
                then_ops: vec![
                    StackOp::Opcode("OP_1SUB".into()),            // skip: digit--
                ],
                else_ops: vec![
                    StackOp::Swap,                                  // pubSeed digit X
                    StackOp::Push(PushValue::Int(2)),
                    StackOp::Opcode("OP_PICK".into()),            // copy pubSeed
                    StackOp::Push(PushValue::Bytes(adrs_bytes)),   // ADRS [chainIndex, j]
                    StackOp::Opcode("OP_CAT".into()),              // pubSeed || adrs
                    StackOp::Swap,                                  // bring X to top
                    StackOp::Opcode("OP_CAT".into()),              // pubSeed || adrs || X
                    StackOp::Opcode("OP_SHA256".into()),           // F result
                    StackOp::Swap,                                  // pubSeed new_X digit(=0)
                ],
            });
        }
        self.emit_op(StackOp::Drop); // drop digit (now 0)
        // main: pubSeed endpoint

        // Restore from alt (LIFO): sigRest, csum, endpt_acc, steps_copy
        self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));
        self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));
        self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));
        self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));

        // csum += steps_copy
        self.emit_op(StackOp::Rot);
        self.emit_op(StackOp::Opcode("OP_ADD".into()));

        // Concat endpoint to endpt_acc
        self.emit_op(StackOp::Swap);
        self.emit_op(StackOp::Push(PushValue::Int(3)));
        self.emit_op(StackOp::Opcode("OP_ROLL".into()));
        self.emit_op(StackOp::Opcode("OP_CAT".into()));
    }

    /// WOTS+ signature verification with RFC 8391 tweakable hash (post-quantum).
    /// Parameters: w=16, n=32 (SHA-256), len=67 chains.
    /// pubkey is 64 bytes: pubSeed(32) || pkRoot(32).
    fn lower_verify_wots(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 3, "verifyWOTS requires 3 arguments: msg, sig, pubkey");

        for arg in args.iter() {
            let is_last = self.is_last_use(arg, binding_index, last_uses);
            self.bring_to_top(arg, is_last);
        }
        for _ in 0..3 { self.sm.pop(); }
        // main: msg sig pubkey(64B: pubSeed||pkRoot)

        // Split 64-byte pubkey into pubSeed(32) and pkRoot(32)
        self.emit_op(StackOp::Push(PushValue::Int(32)));
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));          // msg sig pubSeed pkRoot
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));    // pkRoot → alt

        // Rearrange: put pubSeed at bottom, hash msg
        self.emit_op(StackOp::Rot);                                 // sig pubSeed msg
        self.emit_op(StackOp::Rot);                                 // pubSeed msg sig
        self.emit_op(StackOp::Swap);                                // pubSeed sig msg
        self.emit_op(StackOp::Opcode("OP_SHA256".into()));         // pubSeed sig msgHash

        // Canonical layout: pubSeed(bottom) sig csum=0 endptAcc=empty hashRem(top)
        self.emit_op(StackOp::Swap);
        self.emit_op(StackOp::Push(PushValue::Int(0)));
        self.emit_op(StackOp::Opcode("OP_0".into()));
        self.emit_op(StackOp::Push(PushValue::Int(3)));
        self.emit_op(StackOp::Opcode("OP_ROLL".into()));

        // Process 32 bytes → 64 message chains
        for byte_idx in 0..32 {
            if byte_idx < 31 {
                self.emit_op(StackOp::Push(PushValue::Int(1)));
                self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
                self.emit_op(StackOp::Swap);
            }
            // Unsigned byte conversion
            self.emit_op(StackOp::Push(PushValue::Int(0)));
            self.emit_op(StackOp::Push(PushValue::Int(1)));
            self.emit_op(StackOp::Opcode("OP_NUM2BIN".into()));
            self.emit_op(StackOp::Opcode("OP_CAT".into()));
            self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
            // Extract nibbles
            self.emit_op(StackOp::Opcode("OP_DUP".into()));
            self.emit_op(StackOp::Push(PushValue::Int(16)));
            self.emit_op(StackOp::Opcode("OP_DIV".into()));
            self.emit_op(StackOp::Swap);
            self.emit_op(StackOp::Push(PushValue::Int(16)));
            self.emit_op(StackOp::Opcode("OP_MOD".into()));

            if byte_idx < 31 {
                self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));
                self.emit_op(StackOp::Swap);
                self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));
            } else {
                self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));
            }

            self.emit_wots_one_chain(byte_idx * 2); // high nibble chain

            if byte_idx < 31 {
                self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));
                self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));
                self.emit_op(StackOp::Swap);
                self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));
            } else {
                self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));
            }

            self.emit_wots_one_chain(byte_idx * 2 + 1); // low nibble chain

            if byte_idx < 31 {
                self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));
            }
        }

        // Checksum digits
        self.emit_op(StackOp::Swap);
        // d66
        self.emit_op(StackOp::Opcode("OP_DUP".into()));
        self.emit_op(StackOp::Push(PushValue::Int(16)));
        self.emit_op(StackOp::Opcode("OP_MOD".into()));
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));
        // d65
        self.emit_op(StackOp::Opcode("OP_DUP".into()));
        self.emit_op(StackOp::Push(PushValue::Int(16)));
        self.emit_op(StackOp::Opcode("OP_DIV".into()));
        self.emit_op(StackOp::Push(PushValue::Int(16)));
        self.emit_op(StackOp::Opcode("OP_MOD".into()));
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));
        // d64
        self.emit_op(StackOp::Push(PushValue::Int(256)));
        self.emit_op(StackOp::Opcode("OP_DIV".into()));
        self.emit_op(StackOp::Push(PushValue::Int(16)));
        self.emit_op(StackOp::Opcode("OP_MOD".into()));
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));

        // 3 checksum chains (indices 64, 65, 66)
        for ci in 0..3 {
            self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));
            self.emit_op(StackOp::Push(PushValue::Int(0)));
            self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));
            self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into()));
            self.emit_wots_one_chain(64 + ci);
            self.emit_op(StackOp::Swap);
            self.emit_op(StackOp::Drop);
        }

        // Final comparison
        self.emit_op(StackOp::Swap);
        self.emit_op(StackOp::Drop);
        // main: pubSeed endptAcc
        self.emit_op(StackOp::Opcode("OP_SHA256".into()));
        self.emit_op(StackOp::Opcode("OP_FROMALTSTACK".into())); // pkRoot
        self.emit_op(StackOp::Opcode("OP_EQUAL".into()));
        // Clean up pubSeed
        self.emit_op(StackOp::Swap);
        self.emit_op(StackOp::Drop);

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// SLH-DSA (FIPS 205) signature verification.
    /// Brings all 3 args to the top, pops them, delegates to slh_dsa::emit_verify_slh_dsa,
    /// and pushes the boolean result.
    fn lower_verify_slh_dsa(
        &mut self,
        binding_name: &str,
        param_key: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(
            args.len() >= 3,
            "verifySLHDSA requires 3 arguments: msg, sig, pubkey"
        );

        // Bring args to top in order: msg, sig, pubkey
        for arg in args.iter() {
            let is_last = self.is_last_use(arg, binding_index, last_uses);
            self.bring_to_top(arg, is_last);
        }
        for _ in 0..3 {
            self.sm.pop();
        }

        // Delegate to slh_dsa module
        super::slh_dsa::emit_verify_slh_dsa(&mut |op| self.ops.push(op), param_key);

        self.sm.push(binding_name);
        self.track_depth();
    }

    // =========================================================================
    // SHA-256 compression -- delegates to sha256.rs
    // =========================================================================

    fn lower_sha256_compress(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(
            args.len() >= 2,
            "sha256Compress requires 2 arguments: state, block"
        );
        for arg in args.iter() {
            let is_last = self.is_last_use(arg, binding_index, last_uses);
            self.bring_to_top(arg, is_last);
        }
        for _ in 0..2 {
            self.sm.pop();
        }

        super::sha256::emit_sha256_compress(&mut |op| self.ops.push(op));

        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_sha256_finalize(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(
            args.len() >= 3,
            "sha256Finalize requires 3 arguments: state, remaining, msgBitLen"
        );
        for arg in args.iter() {
            let is_last = self.is_last_use(arg, binding_index, last_uses);
            self.bring_to_top(arg, is_last);
        }
        for _ in 0..3 {
            self.sm.pop();
        }

        super::sha256::emit_sha256_finalize(&mut |op| self.ops.push(op));

        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_blake3_compress(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(
            args.len() >= 2,
            "blake3Compress requires 2 arguments: chainingValue, block"
        );
        for arg in args.iter() {
            let is_last = self.is_last_use(arg, binding_index, last_uses);
            self.bring_to_top(arg, is_last);
        }
        for _ in 0..2 {
            self.sm.pop();
        }

        super::blake3::emit_blake3_compress(&mut |op| self.ops.push(op));

        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_blake3_hash(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(
            args.len() >= 1,
            "blake3Hash requires 1 argument: message"
        );
        for arg in args.iter() {
            let is_last = self.is_last_use(arg, binding_index, last_uses);
            self.bring_to_top(arg, is_last);
        }
        for _ in 0..1 {
            self.sm.pop();
        }

        super::blake3::emit_blake3_hash(&mut |op| self.ops.push(op));

        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_ec_builtin(
        &mut self,
        binding_name: &str,
        func_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // Bring args to top in order
        for arg in args.iter() {
            let is_last = self.is_last_use(arg, binding_index, last_uses);
            self.bring_to_top(arg, is_last);
        }
        for _ in args {
            self.sm.pop();
        }

        let emit = &mut |op: StackOp| self.ops.push(op);

        match func_name {
            "ecAdd" => super::ec::emit_ec_add(emit),
            "ecMul" => super::ec::emit_ec_mul(emit),
            "ecMulGen" => super::ec::emit_ec_mul_gen(emit),
            "ecNegate" => super::ec::emit_ec_negate(emit),
            "ecOnCurve" => super::ec::emit_ec_on_curve(emit),
            "ecModReduce" => super::ec::emit_ec_mod_reduce(emit),
            "ecEncodeCompressed" => super::ec::emit_ec_encode_compressed(emit),
            "ecMakePoint" => super::ec::emit_ec_make_point(emit),
            "ecPointX" => super::ec::emit_ec_point_x(emit),
            "ecPointY" => super::ec::emit_ec_point_y(emit),
            _ => panic!("unknown EC builtin: {}", func_name),
        }

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// safediv(a, b): a / b with division-by-zero check.
    /// Stack: a b -> OP_DUP OP_0NOTEQUAL OP_VERIFY OP_DIV -> result
    fn lower_safediv(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 2, "safediv requires 2 arguments");

        let a_is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], a_is_last);

        let b_is_last = self.is_last_use(&args[1], binding_index, last_uses);
        self.bring_to_top(&args[1], b_is_last);

        self.sm.pop();
        self.sm.pop();

        self.emit_op(StackOp::Opcode("OP_DUP".to_string()));
        self.emit_op(StackOp::Opcode("OP_0NOTEQUAL".to_string()));
        self.emit_op(StackOp::Opcode("OP_VERIFY".to_string()));
        self.emit_op(StackOp::Opcode("OP_DIV".to_string()));

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// safemod(a, b): a % b with division-by-zero check.
    /// Stack: a b -> OP_DUP OP_0NOTEQUAL OP_VERIFY OP_MOD -> result
    fn lower_safemod(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 2, "safemod requires 2 arguments");

        let a_is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], a_is_last);

        let b_is_last = self.is_last_use(&args[1], binding_index, last_uses);
        self.bring_to_top(&args[1], b_is_last);

        self.sm.pop();
        self.sm.pop();

        self.emit_op(StackOp::Opcode("OP_DUP".to_string()));
        self.emit_op(StackOp::Opcode("OP_0NOTEQUAL".to_string()));
        self.emit_op(StackOp::Opcode("OP_VERIFY".to_string()));
        self.emit_op(StackOp::Opcode("OP_MOD".to_string()));

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// clamp(val, lo, hi): clamp val to [lo, hi].
    /// Stack: val lo hi -> val lo OP_MAX hi OP_MIN -> result
    fn lower_clamp(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 3, "clamp requires 3 arguments");

        let val_is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], val_is_last);

        let lo_is_last = self.is_last_use(&args[1], binding_index, last_uses);
        self.bring_to_top(&args[1], lo_is_last);

        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_MAX".to_string()));
        self.sm.push(""); // intermediate result

        let hi_is_last = self.is_last_use(&args[2], binding_index, last_uses);
        self.bring_to_top(&args[2], hi_is_last);

        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_MIN".to_string()));

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// pow(base, exp): base^exp via 32-iteration bounded conditional multiply.
    /// Strategy: swap to get exp base, push 1 (acc), then 32 rounds of:
    ///   2 OP_PICK (get exp), push(i+1), OP_GREATERTHAN, OP_IF, OP_OVER, OP_MUL, OP_ENDIF
    /// After iterations: OP_NIP OP_NIP to get result.
    fn lower_pow(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 2, "pow requires 2 arguments");

        let base_is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], base_is_last);

        let exp_is_last = self.is_last_use(&args[1], binding_index, last_uses);
        self.bring_to_top(&args[1], exp_is_last);

        self.sm.pop();
        self.sm.pop();

        // Stack: base exp
        self.emit_op(StackOp::Swap);                                  // exp base
        self.emit_op(StackOp::Push(PushValue::Int(1)));               // exp base 1(acc)

        for i in 0..32 {
            // Stack: exp base acc
            self.emit_op(StackOp::Push(PushValue::Int(2)));
            self.emit_op(StackOp::Opcode("OP_PICK".to_string()));     // exp base acc exp
            self.emit_op(StackOp::Push(PushValue::Int(i)));
            self.emit_op(StackOp::Opcode("OP_GREATERTHAN".to_string())); // exp base acc (exp > i)
            self.emit_op(StackOp::If {
                then_ops: vec![
                    StackOp::Over,                                    // exp base acc base
                    StackOp::Opcode("OP_MUL".to_string()),           // exp base (acc*base)
                ],
                else_ops: vec![],
            });
        }
        // Stack: exp base result
        self.emit_op(StackOp::Nip);                                   // exp result
        self.emit_op(StackOp::Nip);                                   // result

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// mulDiv(a, b, c): (a * b) / c
    /// Stack: a b c -> a b OP_MUL c OP_DIV -> result
    fn lower_mul_div(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 3, "mulDiv requires 3 arguments");

        let a_is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], a_is_last);

        let b_is_last = self.is_last_use(&args[1], binding_index, last_uses);
        self.bring_to_top(&args[1], b_is_last);

        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_MUL".to_string()));
        self.sm.push(""); // a*b

        let c_is_last = self.is_last_use(&args[2], binding_index, last_uses);
        self.bring_to_top(&args[2], c_is_last);

        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_DIV".to_string()));

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// percentOf(amount, bps): (amount * bps) / 10000
    /// Stack: amount bps -> OP_MUL 10000 OP_DIV -> result
    fn lower_percent_of(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 2, "percentOf requires 2 arguments");

        let amount_is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], amount_is_last);

        let bps_is_last = self.is_last_use(&args[1], binding_index, last_uses);
        self.bring_to_top(&args[1], bps_is_last);

        self.sm.pop();
        self.sm.pop();

        self.emit_op(StackOp::Opcode("OP_MUL".to_string()));
        self.emit_op(StackOp::Push(PushValue::Int(10000)));
        self.emit_op(StackOp::Opcode("OP_DIV".to_string()));

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// sqrt(n): integer square root via Newton's method, 16 iterations.
    /// Uses: guess = n, then 16x: guess = (guess + n/guess) / 2
    /// Guards against n == 0 to avoid division by zero.
    fn lower_sqrt(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(!args.is_empty(), "sqrt requires 1 argument");

        let n_is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], n_is_last);

        self.sm.pop();

        // Stack: n
        // Guard: if n == 0, skip Newton iteration entirely (result is 0).
        self.emit_op(StackOp::Opcode("OP_DUP".to_string()));
        // Stack: n n

        // Build the Newton iteration ops inside the OP_IF branch
        let mut newton_ops = Vec::new();
        // Stack inside IF: n  (the DUP'd copy was consumed by OP_IF)
        // DUP to get initial guess = n
        newton_ops.push(StackOp::Opcode("OP_DUP".to_string()));
        // Stack: n guess

        // 16 iterations of Newton's method: guess = (guess + n/guess) / 2
        for _ in 0..16 {
            // Stack: n guess
            newton_ops.push(StackOp::Over);                               // n guess n
            newton_ops.push(StackOp::Over);                               // n guess n guess
            newton_ops.push(StackOp::Opcode("OP_DIV".to_string()));      // n guess (n/guess)
            newton_ops.push(StackOp::Opcode("OP_ADD".to_string()));      // n (guess + n/guess)
            newton_ops.push(StackOp::Push(PushValue::Int(2)));            // n (guess + n/guess) 2
            newton_ops.push(StackOp::Opcode("OP_DIV".to_string()));      // n new_guess
        }

        // Stack: n guess
        // Drop n, keep guess
        newton_ops.push(StackOp::Opcode("OP_NIP".to_string()));

        self.emit_op(StackOp::If {
            then_ops: newton_ops,
            else_ops: vec![],  // n == 0, result is already 0 on stack
        });

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// gcd(a, b): Euclidean algorithm, 256 iterations with conditional OP_IF.
    /// Each iteration: if b != 0 then (b, a % b) else (a, 0)
    fn lower_gcd(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 2, "gcd requires 2 arguments");

        let a_is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], a_is_last);

        let b_is_last = self.is_last_use(&args[1], binding_index, last_uses);
        self.bring_to_top(&args[1], b_is_last);

        self.sm.pop();
        self.sm.pop();

        // Stack: a b
        // Both should be absolute values
        self.emit_op(StackOp::Opcode("OP_ABS".to_string()));
        self.emit_op(StackOp::Swap);
        self.emit_op(StackOp::Opcode("OP_ABS".to_string()));
        self.emit_op(StackOp::Swap);
        // Stack: |a| |b|

        // 256 iterations of Euclidean algorithm
        for _ in 0..256 {
            // Stack: a b
            // Check if b != 0
            self.emit_op(StackOp::Opcode("OP_DUP".to_string()));      // a b b
            self.emit_op(StackOp::Opcode("OP_0NOTEQUAL".to_string())); // a b (b!=0)

            self.emit_op(StackOp::If {
                then_ops: vec![
                    // Stack: a b (b != 0)
                    // Compute a % b, then swap: new a = b, new b = a%b
                    StackOp::Opcode("OP_TUCK".to_string()),            // b a b
                    StackOp::Opcode("OP_MOD".to_string()),             // b (a%b)
                ],
                else_ops: vec![
                    // Stack: a b (b == 0), just keep as-is
                ],
            });
        }

        // Stack: a b (where b should be 0)
        // Drop b, keep a (the GCD)
        self.emit_op(StackOp::Drop);

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// divmod(a, b): computes both a/b and a%b, returns a/b (drops a%b).
    /// Stack: a b -> OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD OP_DROP -> quotient
    fn lower_divmod(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 2, "divmod requires 2 arguments");

        let a_is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], a_is_last);

        let b_is_last = self.is_last_use(&args[1], binding_index, last_uses);
        self.bring_to_top(&args[1], b_is_last);

        self.sm.pop();
        self.sm.pop();

        // Stack: a b
        self.emit_op(StackOp::Opcode("OP_2DUP".to_string()));         // a b a b
        self.emit_op(StackOp::Opcode("OP_DIV".to_string()));          // a b (a/b)
        self.emit_op(StackOp::Opcode("OP_ROT".to_string()));          // a (a/b) b
        self.emit_op(StackOp::Opcode("OP_ROT".to_string()));          // (a/b) b a
        self.emit_op(StackOp::Opcode("OP_MOD".to_string()));          // (a/b) (a%b) -- wait
        // ROT ROT on a b (a/b): ROT -> b (a/b) a, ROT -> (a/b) a b
        // Then MOD -> (a/b) (a%b)
        // DROP -> (a/b)
        self.emit_op(StackOp::Drop);

        self.sm.push(binding_name);
        self.track_depth();
    }

    /// log2(n): exact floor(log2(n)) via bit-scanning.
    ///
    /// Uses a bounded unrolled loop (64 iterations for bigint range):
    ///   counter = 0
    ///   while input > 1: input >>= 1, counter++
    ///   result = counter
    ///
    /// Stack layout during loop: <input> <counter>
    /// Each iteration: OP_SWAP OP_DUP 1 OP_GREATERTHAN OP_IF 2 OP_DIV OP_SWAP OP_1ADD OP_SWAP OP_ENDIF OP_SWAP
    fn lower_log2(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(!args.is_empty(), "log2 requires 1 argument");

        let n_is_last = self.is_last_use(&args[0], binding_index, last_uses);
        self.bring_to_top(&args[0], n_is_last);

        self.sm.pop();

        // Stack: <n>
        // Push counter = 0
        self.emit_op(StackOp::Push(PushValue::Int(0))); // n 0

        // 64 iterations (sufficient for Bitcoin Script bigint range)
        const LOG2_ITERATIONS: usize = 64;
        for _ in 0..LOG2_ITERATIONS {
            // Stack: input counter
            self.emit_op(StackOp::Swap);                                     // counter input
            self.emit_op(StackOp::Opcode("OP_DUP".to_string()));            // counter input input
            self.emit_op(StackOp::Push(PushValue::Int(1)));                  // counter input input 1
            self.emit_op(StackOp::Opcode("OP_GREATERTHAN".to_string()));     // counter input (input>1)
            self.emit_op(StackOp::If {
                then_ops: vec![
                    StackOp::Push(PushValue::Int(2)),                        // counter input 2
                    StackOp::Opcode("OP_DIV".to_string()),                   // counter (input/2)
                    StackOp::Swap,                                           // (input/2) counter
                    StackOp::Opcode("OP_1ADD".to_string()),                  // (input/2) (counter+1)
                    StackOp::Swap,                                           // (counter+1) (input/2)
                ],
                else_ops: vec![],
            });
            // Stack: counter input (or input counter if swapped back)
            // After the if: stack is counter input (swap at start, then if-branch swaps back)
            self.emit_op(StackOp::Swap);                                     // input counter
        }
        // Stack: input counter
        // Drop input, keep counter
        self.emit_op(StackOp::Nip); // counter

        self.sm.push(binding_name);
        self.track_depth();
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Lower an ANF program to Stack IR.
/// Private methods are inlined at call sites rather than compiled separately.
/// The constructor is skipped since it's not emitted to Bitcoin Script.
pub fn lower_to_stack(program: &ANFProgram) -> Result<Vec<StackMethod>, String> {
    // Build map of private methods for inlining
    let mut private_methods: HashMap<String, ANFMethod> = HashMap::new();
    for method in &program.methods {
        if !method.is_public && method.name != "constructor" {
            private_methods.insert(method.name.clone(), method.clone());
        }
    }

    let mut methods = Vec::new();

    for method in &program.methods {
        // Skip constructor and private methods
        if method.name == "constructor" || (!method.is_public && method.name != "constructor") {
            continue;
        }
        let sm = lower_method_with_private_methods(method, &program.properties, &private_methods)?;
        methods.push(sm);
    }

    Ok(methods)
}

/// Check whether a method's body contains a CheckPreimage binding.
/// If found, the unlocking script will push an implicit <sig> parameter before
/// all declared parameters (OP_PUSH_TX pattern).
fn method_uses_check_preimage(bindings: &[ANFBinding]) -> bool {
    bindings.iter().any(|b| matches!(&b.value, ANFValue::CheckPreimage { .. }))
}

/// Check whether a method has add_output, add_raw_output, or computeStateOutput/
/// computeStateOutputHash calls (recursively). Only methods that construct
/// continuation outputs need the _codePart implicit parameter.
fn method_uses_code_part(bindings: &[ANFBinding]) -> bool {
    bindings.iter().any(|b| match &b.value {
        ANFValue::AddOutput { .. } | ANFValue::AddRawOutput { .. } => true,
        ANFValue::Call { func, .. } if func == "computeStateOutput" || func == "computeStateOutputHash" => true,
        ANFValue::If { then, else_branch, .. } => method_uses_code_part(then) || method_uses_code_part(else_branch),
        ANFValue::Loop { body, .. } => method_uses_code_part(body),
        _ => false,
    })
}

fn lower_method_with_private_methods(
    method: &ANFMethod,
    properties: &[ANFProperty],
    private_methods: &HashMap<String, ANFMethod>,
) -> Result<StackMethod, String> {
    let mut param_names: Vec<String> = method.params.iter().map(|p| p.name.clone()).collect();

    // If the method uses checkPreimage, the unlocking script pushes implicit
    // params before all declared parameters (OP_PUSH_TX pattern).
    // _codePart: full code script (locking script minus state) as ByteString
    // _opPushTxSig: ECDSA signature for OP_PUSH_TX verification
    // These are inserted at the base of the stack so they can be consumed later.
    if method_uses_check_preimage(&method.body) {
        param_names.insert(0, "_opPushTxSig".to_string());
        // _codePart is needed when the method has add_output or add_raw_output
        // (it provides the code script for continuation output construction),
        // or when deserializing variable-length (ByteString) state fields.
        if method_uses_code_part(&method.body) {
            param_names.insert(0, "_codePart".to_string());
        }
    }

    let mut ctx = LoweringContext::new(&param_names, properties);
    ctx.private_methods = private_methods.clone();
    // Pass terminal_assert=true for public methods so the last assert leaves
    // its value on the stack (Bitcoin Script requires a truthy top-of-stack).
    ctx.lower_bindings(&method.body, method.is_public);

    // Clean up excess stack items left by deserialize_state.
    let has_deserialize_state = method.body.iter().any(|b| matches!(&b.value, ANFValue::DeserializeState { .. }));
    if method.is_public && has_deserialize_state && ctx.sm.depth() > 1 {
        let excess = ctx.sm.depth() - 1;
        for _ in 0..excess {
            ctx.emit_op(StackOp::Nip);
            ctx.sm.remove_at_depth(1);
        }
    }

    if ctx.max_depth > MAX_STACK_DEPTH {
        return Err(format!(
            "method '{}' exceeds maximum stack depth of {} (actual: {}). Simplify the contract logic.",
            method.name, MAX_STACK_DEPTH, ctx.max_depth
        ));
    }

    Ok(StackMethod {
        name: method.name.clone(),
        ops: ctx.ops,
        max_stack_depth: ctx.max_depth,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    if hex_str.is_empty() {
        return Vec::new();
    }
    assert!(
        hex_str.len() % 2 == 0,
        "invalid hex string length: {}",
        hex_str.len()
    );
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap_or(0))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFProperty, ANFValue};

    /// Build a minimal P2PKH IR program for testing stack lowering.
    fn p2pkh_program() -> ANFProgram {
        ANFProgram {
            contract_name: "P2PKH".to_string(),
            properties: vec![ANFProperty {
                name: "pubKeyHash".to_string(),
                prop_type: "Addr".to_string(),
                readonly: true,
                initial_value: None,
            }],
            methods: vec![ANFMethod {
                name: "unlock".to_string(),
                params: vec![
                    ANFParam {
                        name: "sig".to_string(),
                        param_type: "Sig".to_string(),
                    },
                    ANFParam {
                        name: "pubKey".to_string(),
                        param_type: "PubKey".to_string(),
                    },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam {
                            name: "sig".to_string(),
                        },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::LoadParam {
                            name: "pubKey".to_string(),
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadProp {
                            name: "pubKeyHash".to_string(),
                        },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::Call {
                            func: "hash160".to_string(),
                            args: vec!["t1".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::BinOp {
                            op: "===".to_string(),
                            left: "t3".to_string(),
                            right: "t2".to_string(),
                            result_type: None,
                        },
                    },
                    ANFBinding {
                        name: "t5".to_string(),
                        value: ANFValue::Assert {
                            value: "t4".to_string(),
                        },
                    },
                    ANFBinding {
                        name: "t6".to_string(),
                        value: ANFValue::Call {
                            func: "checkSig".to_string(),
                            args: vec!["t0".to_string(), "t1".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t7".to_string(),
                        value: ANFValue::Assert {
                            value: "t6".to_string(),
                        },
                    },
                ],
                is_public: true,
            }],
        }
    }

    #[test]
    fn test_p2pkh_stack_lowering_produces_placeholder_ops() {
        let program = p2pkh_program();
        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].name, "unlock");

        // There should be at least one Placeholder op (for the pubKeyHash property)
        let has_placeholder = methods[0].ops.iter().any(|op| {
            matches!(op, StackOp::Placeholder { .. })
        });
        assert!(
            has_placeholder,
            "P2PKH should have Placeholder ops for constructor params, ops: {:?}",
            methods[0].ops
        );
    }

    #[test]
    fn test_placeholder_has_correct_param_index() {
        let program = p2pkh_program();
        let methods = lower_to_stack(&program).expect("stack lowering should succeed");

        // Find the Placeholder op and check its param_index
        let placeholders: Vec<&StackOp> = methods[0]
            .ops
            .iter()
            .filter(|op| matches!(op, StackOp::Placeholder { .. }))
            .collect();

        assert!(
            !placeholders.is_empty(),
            "should have at least one Placeholder"
        );

        // pubKeyHash is the only property at index 0
        if let StackOp::Placeholder {
            param_index,
            param_name,
        } = placeholders[0]
        {
            assert_eq!(*param_index, 0);
            assert_eq!(param_name, "pubKeyHash");
        } else {
            panic!("expected Placeholder op");
        }
    }

    #[test]
    fn test_with_initial_values_no_placeholder_ops() {
        let mut program = p2pkh_program();
        // Set an initial value for the property -- this bakes it in
        program.properties[0].initial_value =
            Some(serde_json::Value::String("aabbccdd".to_string()));

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let has_placeholder = methods[0].ops.iter().any(|op| {
            matches!(op, StackOp::Placeholder { .. })
        });
        assert!(
            !has_placeholder,
            "with initial values, there should be no Placeholder ops"
        );
    }

    #[test]
    fn test_stack_lowering_produces_standard_opcodes() {
        let program = p2pkh_program();
        let methods = lower_to_stack(&program).expect("stack lowering should succeed");

        // Collect all Opcode strings
        let opcodes: Vec<&str> = methods[0]
            .ops
            .iter()
            .filter_map(|op| match op {
                StackOp::Opcode(code) => Some(code.as_str()),
                _ => None,
            })
            .collect();

        // P2PKH should contain OP_HASH160, OP_NUMEQUAL (from ===), OP_VERIFY, OP_CHECKSIG
        assert!(
            opcodes.contains(&"OP_HASH160"),
            "expected OP_HASH160 in opcodes: {:?}",
            opcodes
        );
        assert!(
            opcodes.contains(&"OP_CHECKSIG"),
            "expected OP_CHECKSIG in opcodes: {:?}",
            opcodes
        );
    }

    #[test]
    fn test_max_stack_depth_is_tracked() {
        let program = p2pkh_program();
        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        assert!(
            methods[0].max_stack_depth > 0,
            "max_stack_depth should be > 0"
        );
        // P2PKH has 2 params + some intermediates, so depth should be reasonable
        assert!(
            methods[0].max_stack_depth <= 10,
            "max_stack_depth should be reasonable for P2PKH, got: {}",
            methods[0].max_stack_depth
        );
    }

    // -----------------------------------------------------------------------
    // Helper: collect all opcodes from a StackOp list (including inside If)
    // -----------------------------------------------------------------------

    fn collect_all_opcodes(ops: &[StackOp]) -> Vec<String> {
        let mut result = Vec::new();
        for op in ops {
            match op {
                StackOp::Opcode(code) => result.push(code.clone()),
                StackOp::If { then_ops, else_ops } => {
                    result.push("OP_IF".to_string());
                    result.extend(collect_all_opcodes(then_ops));
                    result.push("OP_ELSE".to_string());
                    result.extend(collect_all_opcodes(else_ops));
                    result.push("OP_ENDIF".to_string());
                }
                StackOp::Push(PushValue::Int(n)) => {
                    result.push(format!("PUSH({})", n));
                }
                StackOp::Drop => result.push("OP_DROP".to_string()),
                StackOp::Swap => result.push("OP_SWAP".to_string()),
                StackOp::Dup => result.push("OP_DUP".to_string()),
                StackOp::Over => result.push("OP_OVER".to_string()),
                StackOp::Rot => result.push("OP_ROT".to_string()),
                StackOp::Nip => result.push("OP_NIP".to_string()),
                _ => {}
            }
        }
        result
    }

    fn collect_opcodes_in_if_branches(ops: &[StackOp]) -> (Vec<String>, Vec<String>) {
        for op in ops {
            if let StackOp::If { then_ops, else_ops } = op {
                return (collect_all_opcodes(then_ops), collect_all_opcodes(else_ops));
            }
        }
        (vec![], vec![])
    }

    // -----------------------------------------------------------------------
    // Fix #1: extractOutputHash offset must be 40, not 44
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_output_hash_uses_offset_40() {
        // Build a stateful contract that calls extractOutputHash on a preimage
        let program = ANFProgram {
            contract_name: "TestExtract".to_string(),
            properties: vec![ANFProperty {
                name: "val".to_string(),
                prop_type: "bigint".to_string(),
                readonly: false,
                initial_value: Some(serde_json::Value::Number(serde_json::Number::from(0))),
            }],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![
                    ANFParam { name: "preimage".to_string(), param_type: "SigHashPreimage".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "preimage".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "extractOutputHash".to_string(),
                            args: vec!["t0".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst { value: serde_json::Value::Bool(true) },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::Assert { value: "t2".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let opcodes = collect_all_opcodes(&methods[0].ops);

        // The offset 40 should appear as PUSH(40), not PUSH(44)
        assert!(
            opcodes.contains(&"PUSH(40)".to_string()),
            "extractOutputHash should use offset 40 (BIP-143 hashOutputs starts at size-40), ops: {:?}",
            opcodes
        );
        assert!(
            !opcodes.contains(&"PUSH(44)".to_string()),
            "extractOutputHash should NOT use offset 44, ops: {:?}",
            opcodes
        );
    }

    // -----------------------------------------------------------------------
    // Fix #3: Terminal-if propagation
    // -----------------------------------------------------------------------

    #[test]
    fn test_terminal_if_propagates_terminal_assert() {
        // A public method ending with if/else where both branches have asserts.
        // The terminal asserts in both branches should NOT emit OP_VERIFY.
        let program = ANFProgram {
            contract_name: "TerminalIf".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![
                    ANFParam { name: "mode".to_string(), param_type: "boolean".to_string() },
                    ANFParam { name: "x".to_string(), param_type: "bigint".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "mode".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::LoadParam { name: "x".to_string() },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::If {
                            cond: "t0".to_string(),
                            then: vec![
                                ANFBinding {
                                    name: "t3".to_string(),
                                    value: ANFValue::LoadConst {
                                        value: serde_json::Value::Number(serde_json::Number::from(10)),
                                    },
                                },
                                ANFBinding {
                                    name: "t4".to_string(),
                                    value: ANFValue::BinOp {
                                        op: ">".to_string(),
                                        left: "t1".to_string(),
                                        right: "t3".to_string(),
                                        result_type: None,
                                    },
                                },
                                ANFBinding {
                                    name: "t5".to_string(),
                                    value: ANFValue::Assert { value: "t4".to_string() },
                                },
                            ],
                            else_branch: vec![
                                ANFBinding {
                                    name: "t6".to_string(),
                                    value: ANFValue::LoadConst {
                                        value: serde_json::Value::Number(serde_json::Number::from(5)),
                                    },
                                },
                                ANFBinding {
                                    name: "t7".to_string(),
                                    value: ANFValue::BinOp {
                                        op: ">".to_string(),
                                        left: "t1".to_string(),
                                        right: "t6".to_string(),
                                        result_type: None,
                                    },
                                },
                                ANFBinding {
                                    name: "t8".to_string(),
                                    value: ANFValue::Assert { value: "t7".to_string() },
                                },
                            ],
                        },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");

        // Get the opcodes inside the if branches
        let (then_opcodes, else_opcodes) = collect_opcodes_in_if_branches(&methods[0].ops);

        // Neither branch should contain OP_VERIFY — the asserts are terminal
        assert!(
            !then_opcodes.contains(&"OP_VERIFY".to_string()),
            "then branch should not contain OP_VERIFY (terminal assert), got: {:?}",
            then_opcodes
        );
        assert!(
            !else_opcodes.contains(&"OP_VERIFY".to_string()),
            "else branch should not contain OP_VERIFY (terminal assert), got: {:?}",
            else_opcodes
        );
    }

    // -----------------------------------------------------------------------
    // Fix #8: pack/unpack/toByteString builtins
    // -----------------------------------------------------------------------

    #[test]
    fn test_unpack_emits_bin2num() {
        let program = ANFProgram {
            contract_name: "TestUnpack".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![
                    ANFParam { name: "data".to_string(), param_type: "ByteString".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "data".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "unpack".to_string(),
                            args: vec!["t0".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Number(serde_json::Number::from(42)),
                        },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::BinOp {
                            op: "===".to_string(),
                            left: "t1".to_string(),
                            right: "t2".to_string(),
                            result_type: None,
                        },
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::Assert { value: "t3".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let opcodes = collect_all_opcodes(&methods[0].ops);
        assert!(
            opcodes.contains(&"OP_BIN2NUM".to_string()),
            "unpack should emit OP_BIN2NUM, got: {:?}",
            opcodes
        );
    }

    #[test]
    fn test_pack_is_noop() {
        let program = ANFProgram {
            contract_name: "TestPack".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![
                    ANFParam { name: "x".to_string(), param_type: "bigint".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "x".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "pack".to_string(),
                            args: vec!["t0".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Bool(true),
                        },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::Assert { value: "t2".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let opcodes = collect_all_opcodes(&methods[0].ops);
        // pack should NOT emit any conversion opcode — just pass through
        assert!(
            !opcodes.contains(&"OP_BIN2NUM".to_string()),
            "pack should not emit OP_BIN2NUM, got: {:?}",
            opcodes
        );
        assert!(
            !opcodes.contains(&"OP_NUM2BIN".to_string()),
            "pack should not emit OP_NUM2BIN, got: {:?}",
            opcodes
        );
    }

    #[test]
    fn test_to_byte_string_is_noop() {
        let program = ANFProgram {
            contract_name: "TestToByteString".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![
                    ANFParam { name: "x".to_string(), param_type: "bigint".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "x".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "toByteString".to_string(),
                            args: vec!["t0".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Bool(true),
                        },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::Assert { value: "t2".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let opcodes = collect_all_opcodes(&methods[0].ops);
        // toByteString should NOT emit any conversion opcode — just pass through
        assert!(
            !opcodes.contains(&"OP_BIN2NUM".to_string()),
            "toByteString should not emit OP_BIN2NUM, got: {:?}",
            opcodes
        );
    }

    // -----------------------------------------------------------------------
    // Fix #25: sqrt(0) guard
    // -----------------------------------------------------------------------

    #[test]
    fn test_sqrt_has_zero_guard() {
        let program = ANFProgram {
            contract_name: "TestSqrt".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![
                    ANFParam { name: "n".to_string(), param_type: "bigint".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "n".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "sqrt".to_string(),
                            args: vec!["t0".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Number(serde_json::Number::from(0)),
                        },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::BinOp {
                            op: ">=".to_string(),
                            left: "t1".to_string(),
                            right: "t2".to_string(),
                            result_type: None,
                        },
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::Assert { value: "t3".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let opcodes = collect_all_opcodes(&methods[0].ops);

        // The sqrt implementation should have OP_DUP followed by OP_IF (the zero guard).
        // The DUP duplicates n, then IF checks if n != 0 before Newton iteration.
        let dup_idx = opcodes.iter().position(|o| o == "OP_DUP");
        let if_idx = opcodes.iter().position(|o| o == "OP_IF");

        assert!(
            dup_idx.is_some() && if_idx.is_some(),
            "sqrt should have OP_DUP and OP_IF for zero guard, got: {:?}",
            opcodes
        );
        assert!(
            dup_idx.unwrap() < if_idx.unwrap(),
            "OP_DUP should come before OP_IF in sqrt zero guard, got: {:?}",
            opcodes
        );
    }

    // -----------------------------------------------------------------------
    // Fix #28: Loop cleanup of unused iteration variables
    // -----------------------------------------------------------------------

    #[test]
    fn test_loop_cleans_up_unused_iter_var() {
        // A loop whose body has only asserts (which consume stack values).
        // After the body, the iter var ends up on top of the stack (depth 0),
        // so it should be dropped. The TS reference does this cleanup.
        let program = ANFProgram {
            contract_name: "TestLoopCleanup".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![
                    ANFParam { name: "x".to_string(), param_type: "bigint".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "x".to_string() },
                    },
                    ANFBinding {
                        name: "t_loop".to_string(),
                        value: ANFValue::Loop {
                            count: 3,
                            body: vec![
                                // Body uses x but not iter var __i, and asserts consume
                                ANFBinding {
                                    name: "t1".to_string(),
                                    value: ANFValue::LoadParam { name: "x".to_string() },
                                },
                                ANFBinding {
                                    name: "t2".to_string(),
                                    value: ANFValue::Assert { value: "t1".to_string() },
                                },
                            ],
                            iter_var: "__i".to_string(),
                        },
                    },
                    ANFBinding {
                        name: "t_final".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Bool(true),
                        },
                    },
                    ANFBinding {
                        name: "t_assert".to_string(),
                        value: ANFValue::Assert { value: "t_final".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let opcodes = collect_all_opcodes(&methods[0].ops);

        // Each iteration pushes __i, then the body asserts (consuming its value).
        // After each iteration, __i is on top (depth 0) and should be dropped.
        // With 3 iterations, we expect at least 3 OP_DROP ops (one per iter var cleanup).
        let drop_count = opcodes.iter().filter(|o| o.as_str() == "OP_DROP").count();
        assert!(
            drop_count >= 3,
            "unused iter var should be dropped after each iteration; expected >= 3 OP_DROPs, got {}: {:?}",
            drop_count,
            opcodes
        );
    }

    // -----------------------------------------------------------------------
    // Fix #29: PushValue::Int uses i128 (no overflow for large values)
    // -----------------------------------------------------------------------

    #[test]
    fn test_push_value_int_large_values() {
        // Verify that PushValue::Int can hold values larger than i64::MAX
        let large_val: i128 = (i64::MAX as i128) + 1;
        let push = PushValue::Int(large_val);
        if let PushValue::Int(v) = push {
            assert_eq!(v, large_val, "PushValue::Int should store values > i64::MAX without truncation");
        } else {
            panic!("expected PushValue::Int");
        }

        // Also test negative extreme
        let neg_val: i128 = (i64::MIN as i128) - 1;
        let push_neg = PushValue::Int(neg_val);
        if let PushValue::Int(v) = push_neg {
            assert_eq!(v, neg_val, "PushValue::Int should store values < i64::MIN without truncation");
        } else {
            panic!("expected PushValue::Int");
        }
    }

    #[test]
    fn test_push_value_int_encodes_large_number() {
        // Verify that a large number (> i64::MAX) can be pushed and encoded
        use crate::codegen::emit::encode_push_int;

        let large_val: i128 = 1i128 << 100;
        let (hex, _asm) = encode_push_int(large_val);
        // Should produce a valid hex encoding, not panic or truncate
        assert!(!hex.is_empty(), "encoding of 2^100 should produce non-empty hex");

        // Verify the encoding length is reasonable for a 13-byte number
        // 2^100 needs 13 bytes in script number encoding (sign-magnitude)
        // Push data: 0x0d (length 13) + 13 bytes = 14 bytes = 28 hex chars
        assert!(
            hex.len() >= 26,
            "2^100 should need at least 13 bytes of push data, got hex length {}: {}",
            hex.len(),
            hex
        );
    }

    // -----------------------------------------------------------------------
    // log2 uses bit-scanning (OP_DIV + OP_GREATERTHAN), not byte approx
    // -----------------------------------------------------------------------

    #[test]
    fn test_log2_uses_bit_scanning_not_byte_approx() {
        let program = ANFProgram {
            contract_name: "TestLog2".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![
                    ANFParam { name: "n".to_string(), param_type: "bigint".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "n".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "log2".to_string(),
                            args: vec!["t0".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Number(serde_json::Number::from(0)),
                        },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::BinOp {
                            op: ">=".to_string(),
                            left: "t1".to_string(),
                            right: "t2".to_string(),
                            result_type: None,
                        },
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::Assert { value: "t3".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let opcodes = collect_all_opcodes(&methods[0].ops);

        // The bit-scanning implementation must use OP_DIV and OP_GREATERTHAN
        assert!(
            opcodes.contains(&"OP_DIV".to_string()),
            "log2 should use OP_DIV (bit-scanning), got: {:?}",
            opcodes
        );
        assert!(
            opcodes.contains(&"OP_GREATERTHAN".to_string()),
            "log2 should use OP_GREATERTHAN (bit-scanning), got: {:?}",
            opcodes
        );

        // The old byte-approximation used OP_SIZE and OP_MUL — must NOT be present
        assert!(
            !opcodes.contains(&"OP_SIZE".to_string()),
            "log2 should NOT use OP_SIZE (old byte approximation), got: {:?}",
            opcodes
        );
        assert!(
            !opcodes.contains(&"OP_MUL".to_string()),
            "log2 should NOT use OP_MUL (old byte approximation), got: {:?}",
            opcodes
        );

        // Should have OP_1ADD for counter increment
        assert!(
            opcodes.contains(&"OP_1ADD".to_string()),
            "log2 should use OP_1ADD (counter increment), got: {:?}",
            opcodes
        );
    }

    // -----------------------------------------------------------------------
    // reverseBytes uses OP_SPLIT + OP_CAT (not non-existent OP_REVERSE)
    // -----------------------------------------------------------------------

    #[test]
    fn test_reverse_bytes_uses_split_cat_not_op_reverse() {
        let program = ANFProgram {
            contract_name: "TestReverse".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![
                    ANFParam { name: "data".to_string(), param_type: "ByteString".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "data".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "reverseBytes".to_string(),
                            args: vec!["t0".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Bool(true),
                        },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::Assert { value: "t2".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let opcodes = collect_all_opcodes(&methods[0].ops);

        // Must NOT contain the non-existent OP_REVERSE
        assert!(
            !opcodes.contains(&"OP_REVERSE".to_string()),
            "reverseBytes must NOT emit OP_REVERSE (does not exist), got: {:?}",
            opcodes
        );

        // Must use OP_SPLIT and OP_CAT for byte-by-byte reversal
        assert!(
            opcodes.contains(&"OP_SPLIT".to_string()),
            "reverseBytes should emit OP_SPLIT for byte peeling, got: {:?}",
            opcodes
        );
        assert!(
            opcodes.contains(&"OP_CAT".to_string()),
            "reverseBytes should emit OP_CAT for reassembly, got: {:?}",
            opcodes
        );

        // Should use OP_SIZE to check remaining length
        assert!(
            opcodes.contains(&"OP_SIZE".to_string()),
            "reverseBytes should emit OP_SIZE for length check, got: {:?}",
            opcodes
        );
    }

    // -----------------------------------------------------------------------
    // Test: only public methods appear in stack output (method count)
    // -----------------------------------------------------------------------

    #[test]
    fn test_method_count_matches_public_methods() {
        // P2PKH program has 1 public method (unlock) and 1 constructor (non-public)
        let program = p2pkh_program();
        let methods = lower_to_stack(&program).expect("stack lowering should succeed");

        // Should have exactly 1 method (unlock) — constructor is skipped
        assert_eq!(
            methods.len(),
            1,
            "expected 1 stack method (unlock), got {}: {:?}",
            methods.len(),
            methods.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
        assert_eq!(methods[0].name, "unlock");
    }

    // -----------------------------------------------------------------------
    // Test: multi-method contract has correct number of StackMethods
    // -----------------------------------------------------------------------

    #[test]
    fn test_multi_method_dispatch() {
        let program = ANFProgram {
            contract_name: "Multi".to_string(),
            properties: vec![],
            methods: vec![
                ANFMethod {
                    name: "constructor".to_string(),
                    params: vec![],
                    body: vec![],
                    is_public: false,
                },
                ANFMethod {
                    name: "method1".to_string(),
                    params: vec![ANFParam {
                        name: "x".to_string(),
                        param_type: "bigint".to_string(),
                    }],
                    body: vec![
                        ANFBinding {
                            name: "t0".to_string(),
                            value: ANFValue::LoadParam { name: "x".to_string() },
                        },
                        ANFBinding {
                            name: "t1".to_string(),
                            value: ANFValue::LoadConst {
                                value: serde_json::Value::Number(serde_json::Number::from(42)),
                            },
                        },
                        ANFBinding {
                            name: "t2".to_string(),
                            value: ANFValue::BinOp {
                                op: "===".to_string(),
                                left: "t0".to_string(),
                                right: "t1".to_string(),
                                result_type: None,
                            },
                        },
                        ANFBinding {
                            name: "t3".to_string(),
                            value: ANFValue::Assert { value: "t2".to_string() },
                        },
                    ],
                    is_public: true,
                },
                ANFMethod {
                    name: "method2".to_string(),
                    params: vec![ANFParam {
                        name: "y".to_string(),
                        param_type: "bigint".to_string(),
                    }],
                    body: vec![
                        ANFBinding {
                            name: "t0".to_string(),
                            value: ANFValue::LoadParam { name: "y".to_string() },
                        },
                        ANFBinding {
                            name: "t1".to_string(),
                            value: ANFValue::LoadConst {
                                value: serde_json::Value::Number(serde_json::Number::from(100)),
                            },
                        },
                        ANFBinding {
                            name: "t2".to_string(),
                            value: ANFValue::BinOp {
                                op: "===".to_string(),
                                left: "t0".to_string(),
                                right: "t1".to_string(),
                                result_type: None,
                            },
                        },
                        ANFBinding {
                            name: "t3".to_string(),
                            value: ANFValue::Assert { value: "t2".to_string() },
                        },
                    ],
                    is_public: true,
                },
            ],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        assert_eq!(
            methods.len(),
            2,
            "expected 2 stack methods, got {}: {:?}",
            methods.len(),
            methods.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // Test: extractOutputs uses offset 40, not 44
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_outputs_uses_offset_40() {
        let program = ANFProgram {
            contract_name: "OutputsCheck".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![ANFParam {
                    name: "preimage".to_string(),
                    param_type: "SigHashPreimage".to_string(),
                }],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "preimage".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "extractOutputs".to_string(),
                            args: vec!["t0".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::Assert { value: "t1".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let opcodes = collect_all_opcodes(&methods[0].ops);

        // The offset for extractOutputs should be 40 (hashOutputs(32) + nLocktime(4) + sighashType(4))
        // Encoded as PUSH(40)
        assert!(
            opcodes.contains(&"PUSH(40)".to_string()),
            "expected PUSH(40) for extractOutputs offset, got: {:?}",
            opcodes
        );
        // Must NOT use the old incorrect offset 44
        assert!(
            !opcodes.contains(&"PUSH(44)".to_string()),
            "extractOutputs should NOT use offset 44, got: {:?}",
            opcodes
        );
    }

    // -----------------------------------------------------------------------
    // Test: arithmetic binary op (a + b) produces OP_ADD in stack output
    // Mirrors Go TestLowerToStack_ArithmeticOps
    // -----------------------------------------------------------------------

    #[test]
    fn test_arithmetic_ops_contains_add() {
        // Contract: verify(a, b) { assert(a + b === target) }
        let program = ANFProgram {
            contract_name: "ArithCheck".to_string(),
            properties: vec![ANFProperty {
                name: "target".to_string(),
                prop_type: "bigint".to_string(),
                readonly: true,
                initial_value: None,
            }],
            methods: vec![ANFMethod {
                name: "verify".to_string(),
                params: vec![
                    ANFParam { name: "a".to_string(), param_type: "bigint".to_string() },
                    ANFParam { name: "b".to_string(), param_type: "bigint".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "a".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::LoadParam { name: "b".to_string() },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::BinOp {
                            op: "+".to_string(),
                            left: "t0".to_string(),
                            right: "t1".to_string(),
                            result_type: None,
                        },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::LoadProp { name: "target".to_string() },
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::BinOp {
                            op: "===".to_string(),
                            left: "t2".to_string(),
                            right: "t3".to_string(),
                            result_type: None,
                        },
                    },
                    ANFBinding {
                        name: "t5".to_string(),
                        value: ANFValue::Assert { value: "t4".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let opcodes = collect_all_opcodes(&methods[0].ops);

        // The a + b operation should emit OP_ADD
        assert!(
            opcodes.contains(&"OP_ADD".to_string()),
            "expected OP_ADD in stack ops for 'a + b', got: {:?}",
            opcodes
        );

        // The === comparison should emit OP_NUMEQUAL
        assert!(
            opcodes.contains(&"OP_NUMEQUAL".to_string()),
            "expected OP_NUMEQUAL in stack ops for '===', got: {:?}",
            opcodes
        );
    }

    // -----------------------------------------------------------------------
    // S18: PICK/ROLL depth ≤ max_stack_depth (stack invariant)
    // After lowering P2PKH, verify no Pick or Roll references a depth ≥ max_stack_depth
    // -----------------------------------------------------------------------

    #[test]
    fn test_s18_pick_roll_depth_within_max_stack_depth() {
        let program = p2pkh_program();
        let methods = lower_to_stack(&program).expect("stack lowering should succeed");

        let max_depth = methods[0].max_stack_depth;

        fn check_ops(ops: &[StackOp], max_depth: usize) {
            for op in ops {
                match op {
                    StackOp::Pick { depth } => {
                        assert!(
                            *depth < max_depth,
                            "Pick depth {} must be < max_stack_depth {}",
                            depth,
                            max_depth
                        );
                    }
                    StackOp::Roll { depth } => {
                        assert!(
                            *depth < max_depth,
                            "Roll depth {} must be < max_stack_depth {}",
                            depth,
                            max_depth
                        );
                    }
                    StackOp::If { then_ops, else_ops } => {
                        check_ops(then_ops, max_depth);
                        check_ops(else_ops, max_depth);
                    }
                    _ => {}
                }
            }
        }

        check_ops(&methods[0].ops, max_depth);
    }

    // -----------------------------------------------------------------------
    // Row 190: ByteString concatenation (bin_op "+", result_type="bytes") → OP_CAT
    // Row 189 (bigint add) → OP_ADD is already tested above.
    // -----------------------------------------------------------------------

    #[test]
    fn test_bytestring_concat_emits_op_cat() {
        let program = ANFProgram {
            contract_name: "CatCheck".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "verify".to_string(),
                params: vec![
                    ANFParam { name: "a".to_string(), param_type: "ByteString".to_string() },
                    ANFParam { name: "b".to_string(), param_type: "ByteString".to_string() },
                    ANFParam { name: "expected".to_string(), param_type: "ByteString".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "a".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::LoadParam { name: "b".to_string() },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::BinOp {
                            op: "+".to_string(),
                            left: "t0".to_string(),
                            right: "t1".to_string(),
                            result_type: Some("bytes".to_string()), // ByteString concat
                        },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::LoadParam { name: "expected".to_string() },
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::BinOp {
                            op: "===".to_string(),
                            left: "t2".to_string(),
                            right: "t3".to_string(),
                            result_type: Some("bytes".to_string()),
                        },
                    },
                    ANFBinding {
                        name: "t5".to_string(),
                        value: ANFValue::Assert { value: "t4".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let opcodes = collect_all_opcodes(&methods[0].ops);

        assert!(
            opcodes.contains(&"OP_CAT".to_string()),
            "ByteString '+' (result_type='bytes') should emit OP_CAT; got opcodes: {:?}",
            opcodes
        );
        assert!(
            !opcodes.contains(&"OP_ADD".to_string()),
            "ByteString '+' should NOT emit OP_ADD (that's for bigint); got opcodes: {:?}",
            opcodes
        );
    }

    // -----------------------------------------------------------------------
    // Row 201: log2 emits exactly 64 if-ops with OP_DIV+OP_1ADD
    // (bit-scanning: 64 iterations, one per bit of a 64-bit integer)
    // -----------------------------------------------------------------------

    #[test]
    fn test_log2_emits_64_if_ops() {
        let program = ANFProgram {
            contract_name: "TestLog2Count".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![
                    ANFParam { name: "n".to_string(), param_type: "bigint".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "n".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "log2".to_string(),
                            args: vec!["t0".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Number(serde_json::Number::from(0)),
                        },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::BinOp {
                            op: ">=".to_string(),
                            left: "t1".to_string(),
                            right: "t2".to_string(),
                            result_type: None,
                        },
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::Assert { value: "t3".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let methods = lower_to_stack(&program).expect("stack lowering should succeed");

        // Count OP_IF occurrences — there should be exactly 64 (one per bit)
        fn count_if_ops(ops: &[StackOp]) -> usize {
            let mut count = 0;
            for op in ops {
                match op {
                    StackOp::If { then_ops, else_ops } => {
                        count += 1;
                        count += count_if_ops(then_ops);
                        count += count_if_ops(else_ops);
                    }
                    _ => {}
                }
            }
            count
        }

        let if_count = count_if_ops(&methods[0].ops);
        assert_eq!(
            if_count, 64,
            "log2 should emit exactly 64 if-ops (one per bit); got {} if-ops",
            if_count
        );
    }
}
