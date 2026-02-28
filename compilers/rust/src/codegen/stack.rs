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

use std::collections::HashMap;

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
}

/// Typed value for push operations.
#[derive(Debug, Clone)]
pub enum PushValue {
    Bool(bool),
    Int(i64),
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
        "right" => Some(vec!["OP_SPLIT", "OP_NIP"]),
        "int2str" => Some(vec!["OP_NUM2BIN"]),
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
        ANFValue::LoadParam { .. }
        | ANFValue::LoadProp { .. }
        | ANFValue::GetStateScript {} => {}

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
}

impl LoweringContext {
    fn new(params: &[String], properties: &[ANFProperty]) -> Self {
        let mut ctx = LoweringContext {
            sm: StackMap::new(params),
            ops: Vec::new(),
            max_depth: 0,
            properties: properties.to_vec(),
            private_methods: HashMap::new(),
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
                self.emit_op(StackOp::Push(PushValue::Int(depth as i64)));
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
                self.emit_op(StackOp::Push(PushValue::Int(depth as i64)));
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

    fn lower_bindings(&mut self, bindings: &[ANFBinding]) {
        let last_uses = compute_last_uses(bindings);
        for (i, binding) in bindings.iter().enumerate() {
            self.lower_binding(binding, i, &last_uses);
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
                self.lower_load_const(name, &binding.value);
            }
            ANFValue::BinOp {
                op, left, right, result_type, ..
            } => {
                self.lower_bin_op(name, op, left, right, binding_index, last_uses, result_type.as_deref());
            }
            ANFValue::UnaryOp { op, operand } => {
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
                self.lower_if(name, cond, then, else_branch, binding_index, last_uses);
            }
            ANFValue::Loop {
                count,
                body,
                iter_var,
            } => {
                self.lower_loop(name, *count, body, iter_var);
            }
            ANFValue::Assert { value } => {
                self.lower_assert(value, binding_index, last_uses);
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

        if let Some(ref p) = prop {
            if let Some(ref val) = p.initial_value {
                self.push_json_value(val);
            } else if self.sm.has(prop_name) {
                self.bring_to_top(prop_name, false);
                self.sm.pop();
            } else {
                self.emit_op(StackOp::Push(PushValue::Int(0)));
            }
        } else if self.sm.has(prop_name) {
            self.bring_to_top(prop_name, false);
            self.sm.pop();
        } else {
            self.emit_op(StackOp::Push(PushValue::Int(0)));
        }
        self.sm.push(binding_name);
    }

    fn push_json_value(&mut self, val: &serde_json::Value) {
        match val {
            serde_json::Value::Bool(b) => {
                self.emit_op(StackOp::Push(PushValue::Bool(*b)));
            }
            serde_json::Value::Number(n) => {
                let i = n.as_i64().unwrap_or(0);
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

    fn lower_load_const(&mut self, binding_name: &str, value: &ANFValue) {
        // Handle @ref: aliases (ANF variable aliasing)
        // When a load_const has a string value starting with "@ref:", it's an alias
        // to another binding. We bring that value to the top via PICK (non-consuming).
        if let Some(ConstValue::Str(ref s)) = value.const_value() {
            if s.len() > 5 && &s[..5] == "@ref:" {
                let ref_name = &s[5..];
                if self.sm.has(ref_name) {
                    self.bring_to_top(ref_name, false);
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
        if result_type == Some("bytes") && (op == "===" || op == "!==") {
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
        _object: &str,
        method: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
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
        // First, bring all args to the top of the stack and rename them to the method param names
        for (i, arg) in args.iter().enumerate() {
            if i < method.params.len() {
                let is_last = self.is_last_use(arg, binding_index, last_uses);
                self.bring_to_top(arg, is_last);
                // Rename to param name
                self.sm.pop();
                self.sm.push(&method.params[i].name);
            }
        }

        // Lower the method body
        self.lower_bindings(&method.body);

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
    ) {
        let is_last = self.is_last_use(cond, binding_index, last_uses);
        self.bring_to_top(cond, is_last);
        self.sm.pop(); // OP_IF consumes condition

        // Lower then-branch
        let mut then_ctx = LoweringContext::new(&[], &self.properties);
        then_ctx.sm = self.sm.clone();
        then_ctx.lower_bindings(then_bindings);
        let then_ops = then_ctx.ops;

        // Lower else-branch
        let mut else_ctx = LoweringContext::new(&[], &self.properties);
        else_ctx.sm = self.sm.clone();
        else_ctx.lower_bindings(else_bindings);
        let else_ops = else_ctx.ops;

        self.emit_op(StackOp::If {
            then_ops,
            else_ops: if else_ops.is_empty() {
                Vec::new()
            } else {
                else_ops
            },
        });

        self.sm.push(binding_name);
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
        binding_name: &str,
        count: usize,
        body: &[ANFBinding],
        iter_var: &str,
    ) {
        // Match the TS reference: simply unroll the loop, lowering the body
        // each iteration with regular last-use analysis. Outer-scope variables
        // may be consumed and must be re-established by the body (e.g. via @ref aliases).
        for i in 0..count {
            self.emit_op(StackOp::Push(PushValue::Int(i as i64)));
            self.sm.push(iter_var);
            self.lower_bindings(body);
        }
        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_assert(
        &mut self,
        value_ref: &str,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        let is_last = self.is_last_use(value_ref, binding_index, last_uses);
        self.bring_to_top(value_ref, is_last);
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_VERIFY".to_string()));
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
                self.bring_to_top(&prop.name, false);
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
            }
            // Byte types (ByteString, PubKey, Sig, Sha256, etc.) need no conversion

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
                self.sm.pop();
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
                self.sm.pop();
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
                self.sm.pop();
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
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Drop);
                self.sm.pop();
                self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
            }
            "extractOutputHash" | "extractOutputs" => {
                // End-relative: 32 bytes before the last 8 (nLocktime 4 + sighashType 4).
                // <preimage> OP_SIZE 44 OP_SUB OP_SPLIT OP_NIP 32 OP_SPLIT OP_DROP
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
                self.emit_op(StackOp::Push(PushValue::Int(32)));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
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
                self.sm.pop();
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
                self.sm.pop();
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
                self.sm.pop();
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

        // BSV Genesis protocol provides OP_REVERSE (0xd1) for byte string reversal.
        // This is the most efficient implementation and handles any input length.
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_REVERSE".to_string()));

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
        // Opcode sequence: OP_DUP OP_TOALTSTACK OP_SWAP OP_3 OP_ROLL
        //                  OP_DUP OP_MUL OP_ADD OP_SWAP OP_MOD OP_SWAP OP_SHA256 OP_EQUAL
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
        self.emit_op(StackOp::Opcode("OP_DUP".to_string()));
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".to_string()));
        self.emit_op(StackOp::Opcode("OP_SWAP".to_string()));
        self.emit_op(StackOp::Opcode("OP_3".to_string()));
        self.emit_op(StackOp::Opcode("OP_ROLL".to_string()));
        self.emit_op(StackOp::Opcode("OP_DUP".to_string()));
        self.emit_op(StackOp::Opcode("OP_MUL".to_string()));
        self.emit_op(StackOp::Opcode("OP_ADD".to_string()));
        self.emit_op(StackOp::Opcode("OP_SWAP".to_string()));
        self.emit_op(StackOp::Opcode("OP_MOD".to_string()));
        self.emit_op(StackOp::Opcode("OP_SWAP".to_string()));
        self.emit_op(StackOp::Opcode("OP_SHA256".to_string()));
        self.emit_op(StackOp::Opcode("OP_EQUAL".to_string()));

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

fn lower_method_with_private_methods(
    method: &ANFMethod,
    properties: &[ANFProperty],
    private_methods: &HashMap<String, ANFMethod>,
) -> Result<StackMethod, String> {
    let mut param_names: Vec<String> = method.params.iter().map(|p| p.name.clone()).collect();

    // If the method uses checkPreimage, the unlocking script pushes an
    // implicit <sig> before all declared parameters (OP_PUSH_TX pattern).
    // Insert _opPushTxSig at the base of the stack so it can be consumed
    // by lower_check_preimage later.
    if method_uses_check_preimage(&method.body) {
        param_names.insert(0, "_opPushTxSig".to_string());
    }

    let mut ctx = LoweringContext::new(&param_names, properties);
    ctx.private_methods = private_methods.clone();
    ctx.lower_bindings(&method.body);

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
