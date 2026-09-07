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

use num_bigint::BigInt;
use std::collections::{HashMap, HashSet};

use crate::ir::{ANFBinding, ANFMethod, ANFProgram, ANFProperty, ANFValue, ConstValue, MERGED_LOCAL_TEMP_PREFIX};

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
    /// An opaque opcode-byte span emitted verbatim by a `raw_script` ANF node.
    /// The stack effect is declared via `in_arity` / `out_arity`; the bytes are
    /// never inspected and the peephole optimizer treats this op as a hard
    /// barrier.
    RawBytes {
        bytes: Vec<u8>,
        in_arity: usize,
        out_arity: usize,
    },
}

/// Typed value for push operations.
#[derive(Debug, Clone)]
pub enum PushValue {
    Bool(bool),
    /// Arbitrary-precision integer push.
    ///
    /// Widened from `i128` to `num_bigint::BigInt` so 256-bit constants
    /// (e.g. the secp256k1 group order in schnorr-zkp's s-bound assert)
    /// round-trip through the stack-IR and into the final push-encoded
    /// Bitcoin Script bytes without truncation. Mirrors Go's
    /// `PushValue.Kind="bigint"` (carries `*big.Int`).
    Int(num_bigint::BigInt),
    Bytes(Vec<u8>),
}

/// A stack-lowered method.
#[derive(Debug, Clone)]
pub struct StackMethod {
    pub name: String,
    pub ops: Vec<StackOp>,
    pub max_stack_depth: usize,
    /// Parallel to `ops`: optional source location for each stack operation.
    /// Used for generating source maps in the emit phase.
    pub source_locs: Vec<Option<crate::ir::SourceLocation>>,
    /// True if the unlocking script is prefixed with `_codePart` — needed for
    /// continuation builders OR terminal methods that read variable-length
    /// (ByteString) state (issue #100). Propagated to ABIMethod.uses_code_part.
    pub uses_code_part: bool,
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

fn is_bb_builtin(name: &str) -> bool {
    matches!(
        name,
        "bbFieldAdd" | "bbFieldSub" | "bbFieldMul" | "bbFieldInv"
            | "bbExt4Mul0" | "bbExt4Mul1" | "bbExt4Mul2" | "bbExt4Mul3"
            | "bbExt4Inv0" | "bbExt4Inv1" | "bbExt4Inv2" | "bbExt4Inv3"
    )
}

fn is_kb_builtin(name: &str) -> bool {
    matches!(
        name,
        "kbFieldAdd" | "kbFieldSub" | "kbFieldMul" | "kbFieldInv"
            | "kbExt4Mul0" | "kbExt4Mul1" | "kbExt4Mul2" | "kbExt4Mul3"
            | "kbExt4Inv0" | "kbExt4Inv1" | "kbExt4Inv2" | "kbExt4Inv3"
    )
}

fn is_bn254_builtin(name: &str) -> bool {
    matches!(
        name,
        "bn254FieldAdd"
            | "bn254FieldSub"
            | "bn254FieldMul"
            | "bn254FieldInv"
            | "bn254FieldNeg"
            | "bn254G1Add"
            | "bn254G1ScalarMul"
            | "bn254G1Negate"
            | "bn254G1OnCurve"
    )
}

fn is_nist_ec_builtin(name: &str) -> bool {
    matches!(
        name,
        "p256Add" | "p256Mul" | "p256MulGen"
            | "p256Negate" | "p256OnCurve" | "p256EncodeCompressed"
            | "p384Add" | "p384Mul" | "p384MulGen"
            | "p384Negate" | "p384OnCurve" | "p384EncodeCompressed"
    )
}

fn is_merkle_builtin(name: &str) -> bool {
    matches!(name, "merkleRootSha256" | "merkleRootHash256" | "merkleRootPoseidon2KB")
}

/// State-field types that are stored as script numbers (require OP_BIN2NUM
/// after extraction). `RabinSig`/`RabinPubKey` are bigint aliases.
fn is_numeric_state_type(t: &str) -> bool {
    matches!(t, "bigint" | "boolean" | "RabinSig" | "RabinPubKey")
}

/// State-field types that are stored with a push-data length prefix and thus
/// require `emit_push_data_decode` instead of a fixed OP_SPLIT.
fn is_variable_length_state_type(t: &str) -> bool {
    matches!(t, "ByteString" | "Sig" | "SigHashPreimage")
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

    /// How many slots carry each name. The model resolves a name to its
    /// SHALLOWEST slot, so a name held more than once has one live slot and the
    /// rest are dead residue — but they are all still "the name" to a
    /// set-membership test, which is what NEW-018 turned on. See `lower_if`.
    fn name_counts(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for s in &self.slots {
            if !s.is_empty() {
                *counts.entry(s.clone()).or_insert(0) += 1;
            }
        }
        counts
    }

    /// The depths to drop for a multiset of names, taking the SHALLOWEST
    /// occurrences of a name listed more than once — the shallowest slot is the
    /// live one, and it is the one the sibling arm consumed. Returned
    /// deepest-first so removing a deeper slot does not shift a shallower one.
    /// For a name listed once this is exactly `find_depth`, which also resolves
    /// to the shallowest slot.
    fn drop_depths_for(&self, names: &[String]) -> Vec<usize> {
        let mut need: HashMap<&str, usize> = HashMap::new();
        for n in names {
            *need.entry(n.as_str()).or_insert(0) += 1;
        }
        let mut depths: Vec<usize> = Vec::with_capacity(names.len());
        for d in 0..self.depth() {
            let name = self.peek_at_depth(d);
            if name.is_empty() {
                continue;
            }
            if let Some(want) = need.get_mut(name) {
                if *want > 0 {
                    depths.push(d);
                    *want -= 1;
                }
            }
        }
        depths.sort_by(|a, b| b.cmp(a));
        depths
    }

    /// Debug string of the slot names (bottom -> top) for error messages.
    fn debug_slots(&self) -> String {
        self.slots.join(", ")
    }
}

// ---------------------------------------------------------------------------
// Use analysis
// ---------------------------------------------------------------------------

fn compute_last_uses(bindings: &[ANFBinding]) -> HashMap<String, usize> {
    let mut last_use = HashMap::new();
    // Pre-scan: map each array_literal binding to its element refs. Used to
    // propagate last-use across the array indirection (the array binding is
    // pure metadata in lower_array_literal — its elements must remain live
    // until the array's consumer, not until the array_literal binding itself).
    let mut array_elems: HashMap<String, Vec<String>> = HashMap::new();
    for b in bindings {
        if let ANFValue::ArrayLiteral { elements } = &b.value {
            array_elems.insert(b.name.clone(), elements.clone());
        }
    }
    for (i, binding) in bindings.iter().enumerate() {
        // array_literal is metadata-only — do NOT advance its elements'
        // last-use to here; defer to the array's consumer.
        if matches!(&binding.value, ANFValue::ArrayLiteral { .. }) {
            continue;
        }
        for r in collect_refs(&binding.value) {
            if let Some(elems) = array_elems.get(&r) {
                for e in elems {
                    last_use.insert(e.clone(), i);
                }
            }
            last_use.insert(r, i);
        }
    }
    last_use
}

/// Collect every binding name defined anywhere in a binding sequence,
/// recursing into nested if-branches and loop bodies. Used by lower_loop to
/// distinguish loop-internal (re)definitions from true outer-scope refs.
fn collect_deep_binding_names(bindings: &[ANFBinding]) -> HashSet<String> {
    fn walk(bindings: &[ANFBinding], names: &mut HashSet<String>) {
        for b in bindings {
            names.insert(b.name.clone());
            match &b.value {
                ANFValue::If { then, else_branch, .. } => {
                    walk(then, names);
                    walk(else_branch, names);
                }
                ANFValue::Loop { body, .. } => {
                    walk(body, names);
                }
                _ => {}
            }
        }
    }
    let mut names = HashSet::new();
    walk(bindings, &mut names);
    names
}

/// Locals a loop body REBINDS and then READS AGAIN in the same iteration.
///
/// `compute_last_uses` maps a name to the MAXIMUM index that references it, so
/// for a body like
///
/// ```text
/// t3   = acc + step     (index 1 — reads the value carried in)
/// acc  = @ref:t3        (index 2 — rebinds: renames t3's slot to `acc`)
/// t4   = wacc + acc     (index 3 — reads the value just rebound)
/// ```
///
/// `acc` gets last-use 3. Index 1 is therefore NOT a last use and copies (PICK)
/// instead of consuming, leaving the incoming slot on the stack under the same
/// name as the rebound one; index 3 then IS the last use, and `find_depth`
/// resolves to the topmost match — so it consumes the UPDATED value and leaves
/// the dead incoming one. The next iteration reads that dead slot, and every
/// iteration recomputes from the pre-loop value:
/// `for (let i = 0n; i < N; i++) { acc = acc + step; wacc = wacc + acc; }`
/// produced `wacc = step*N` where the source says `step*N*(N+1)/2` — silently
/// in a stateless contract, and as a permanently unspendable UTXO in a stateful
/// one (the covenant commits to a continuation the SDK never builds).
/// `outer_refs` does not cover it: `acc` is excluded there precisely because the
/// body binds it.
///
/// The value these names hold at the end of an iteration is live at the start of
/// the next one, so `lower_loop` protects them from consumption exactly like an
/// outer ref. The incoming slot each rebinding shadows is left behind and
/// drained with the rest of the frame at method exit — a name always resolves to
/// its newest slot, so the reads stay correct.
///
/// Both halves of the predicate are load-bearing:
///   - read BEFORE the first rebinding: the name is carried IN from the
///     enclosing scope, rather than being a body-private temp that merely
///     happens to be read after it is bound;
///   - read AFTER the last rebinding: without it the rebound value is dead at
///     the end of the iteration and consuming it is correct. This is what keeps
///     every shipped accumulator (`sum = sum + i`, `off = off + len`)
///     byte-for-byte unchanged.
///
/// NESTED loops: the scan runs over `flatten_nested_loop_bodies(body)`, not
/// over `body` itself. A name rebound only inside an INNER loop is bound at no
/// top-level index of the outer body, so the raw scan classified it as neither
/// an outer ref (`collect_deep_binding_names` excludes it — the body does bind
/// it, deeply) nor a carried rebind, and the outer loop never marked it live.
/// The inner loop's final iteration then consumed it, because `used_after_loop`
/// asks the enclosing scope and the enclosing scope had not been told either,
/// so every outer iteration restarted from the slot the previous one left
/// behind: `for (i<2) { for (j<2) { acc = acc + step; wacc = wacc + acc; } }`
/// with step = 3 produced `wacc = 24` where the source says 30. Splicing the
/// inner body in at the loop's position preserves the read/rebind/read ordering
/// the inner level already sees, so the outer level draws the same conclusion.
fn collect_loop_carried_rebinds(body: &[ANFBinding]) -> HashSet<String> {
    let flat = flatten_nested_loop_bodies(body);

    let mut first_bind: HashMap<&str, usize> = HashMap::new();
    let mut last_bind: HashMap<&str, usize> = HashMap::new();
    for (i, b) in flat.iter().enumerate() {
        first_bind.entry(b.name.as_str()).or_insert(i);
        last_bind.insert(b.name.as_str(), i);
    }

    let mut read_before_bind: HashSet<String> = HashSet::new();
    let mut read_after_bind: HashSet<String> = HashSet::new();
    for (i, b) in flat.iter().enumerate() {
        for r in collect_refs(&b.value) {
            if first_bind.get(r.as_str()).is_some_and(|&first| i < first) {
                read_before_bind.insert(r.clone());
            }
            if last_bind.get(r.as_str()).is_some_and(|&last| i > last) {
                read_after_bind.insert(r);
            }
        }
    }

    read_before_bind
        .into_iter()
        .filter(|r| read_after_bind.contains(r))
        .collect()
}

/// The binding sequence with every nested `loop` binding — and every `if`
/// binding — replaced, in place, by its own (recursively flattened) body.
///
/// Only `collect_loop_carried_rebinds` uses this, and only to order reads
/// against rebindings. Neither replaced binding contributes a stack slot that
/// predicate reasons about, so dropping it loses nothing; splicing the sub-body
/// in at its position is what lets an enclosing loop see a rebinding one level
/// down.
///
/// `if` arms ARE spliced, in `then ++ else` order, even though they are
/// alternatives rather than a sequence. The predicate asks only "is this name
/// read, then rebound, then read again", and treating the arms as a sequence
/// can only ADD names to the carried set, never remove one — conservative in
/// the safe direction. Without it a local rebound ONLY inside an `if` arm was
/// bound at no index the predicate could see: neither an outer ref
/// (`deep_body_binding_names` excludes it, since the body does bind it, deeply)
/// nor a carried rebind. The loop consumed it and the next iteration had
/// nothing to read, so `for (i<2) { if (i<5) { acc = acc + step; }
/// wacc = wacc + acc; }` was REJECTED outright with
/// `Value 'acc' not found on stack` — the loud face of the same gap the
/// merged-local protection in `lower_if` fixes silently at K>=2.
///
/// The `if` binding itself is NOT re-appended after its arms. Appending it
/// would count the arms' reads a second time at an index past every arm
/// rebinding, making a local that BOTH arms rebind look "read after its last
/// rebinding" — which protected a K=1 alias that must stay consumable.
///
/// A body with no nested loop and no `if` is returned entry-for-entry
/// unchanged, which is what makes this byte-neutral for every flat loop.
fn flatten_nested_loop_bodies(body: &[ANFBinding]) -> Vec<&ANFBinding> {
    if !body
        .iter()
        .any(|b| matches!(b.value, ANFValue::Loop { .. } | ANFValue::If { .. }))
    {
        return body.iter().collect();
    }
    let mut flat: Vec<&ANFBinding> = Vec::with_capacity(body.len());
    for b in body {
        match &b.value {
            ANFValue::Loop { body: inner, .. } => {
                flat.extend(flatten_nested_loop_bodies(inner));
            }
            ANFValue::If {
                then, else_branch, ..
            } => {
                flat.extend(flatten_nested_loop_bodies(then));
                flat.extend(flatten_nested_loop_bodies(else_branch));
            }
            _ => flat.push(b),
        }
    }
    flat
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
            ..
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
        ANFValue::Assert { value, .. } => {
            refs.push(value.clone());
        }
        ANFValue::UpdateProp { value, .. } => {
            refs.push(value.clone());
        }
        ANFValue::CheckPreimage { preimage, .. } => {
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
        ANFValue::AddDataOutput { satoshis, script_bytes } => {
            refs.push(satoshis.clone());
            refs.push(script_bytes.clone());
        }
        ANFValue::ArrayLiteral { elements } => {
            refs.extend(elements.iter().cloned());
        }
        ANFValue::RawScript { .. } => {
            // Opaque byte span — no SSA operand refs. Stack effect is declared
            // via in_arity / out_arity.
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
    /// Parallel to `ops`: source location for each emitted op.
    source_locs: Vec<Option<crate::ir::SourceLocation>>,
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
    /// Current source location from the ANF binding being lowered.
    current_source_loc: Option<crate::ir::SourceLocation>,
    /// Tracks compile-time constant values by binding name (for Merkle depth extraction, etc.).
    const_values: HashMap<String, ConstValue>,
    /// Element counts for array_literal bindings (used by checkMultiSig).
    array_lengths: HashMap<String, usize>,
    /// Element refs for array_literal bindings (used by checkMultiSig).
    array_elements: HashMap<String, Vec<String>>,
    /// Method params whose names collide with a MUTABLE property. Maps the
    /// param name to the reserved stack-slot name its witness value lives
    /// under, so `lower_load_param` reads the param and not the same-named
    /// deserialized property slot (issue #130). Empty for the common
    /// no-collision case, so all other contracts are byte-identical.
    renamed_params: HashMap<String, String>,
    /// EXPERIMENTAL EC size options (constant pool, sign lattice / reduction
    /// sinking, fixed-base comb), handed down to the EC and NIST curve
    /// emitters. `None` — not an all-false struct — when nothing is enabled, so
    /// those emitters take their untouched default path and the emitted bytes
    /// are provably identical to the shipping ones.
    ec_codegen: Option<super::ec::EcCodegenOptions>,
}

impl LoweringContext {
    fn new(params: &[String], properties: &[ANFProperty]) -> Self {
        let mut ctx = LoweringContext {
            sm: StackMap::new(params),
            ops: Vec::new(),
            source_locs: Vec::new(),
            max_depth: 0,
            properties: properties.to_vec(),
            private_methods: HashMap::new(),
            local_bindings: HashSet::new(),
            outer_protected_refs: None,
            inside_branch: false,
            current_source_loc: None,
            const_values: HashMap::new(),
            array_lengths: HashMap::new(),
            array_elements: HashMap::new(),
            renamed_params: HashMap::new(),
            ec_codegen: None,
        };

        // Issue #130 (stack layer): a method param whose name collides with a
        // MUTABLE property gets a duplicate stackMap slot once
        // `deserialize_state` pushes that property under the same name. Name
        // lookups resolve to the shallowest match (the deserialized property),
        // so `load_param` would read the stale on-chain state instead of the
        // witness value. Rename the colliding param's slot to a reserved,
        // collision-proof name up front and remember the mapping so
        // `lower_load_param` targets the real param slot. Only mutable
        // properties are deserialized onto the stack, so readonly shadows
        // (handled purely by ANF resolution) never enter this map, and
        // non-colliding contracts get an empty map — byte-identical output.
        let mutable_prop_names: HashSet<&str> = properties
            .iter()
            .filter(|p| !p.readonly)
            .map(|p| p.name.as_str())
            .collect();
        for name in params {
            if mutable_prop_names.contains(name.as_str()) {
                if let Some(depth) = ctx.sm.find_depth(name) {
                    let renamed = format!("__param_{}", name);
                    ctx.sm.rename_at_depth(depth, &renamed);
                    ctx.renamed_params.insert(name.clone(), renamed);
                }
            }
        }

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
        self.source_locs.push(self.current_source_loc.clone());
        self.track_depth();
    }

    /// Emit a Bitcoin varint encoding of the length on top of the stack.
    ///
    /// Expects stack: `[..., script, len]`
    /// Leaves stack:  `[..., script, varint_bytes]`
    ///
    /// Bitcoin varint format:
    ///   len < 0xfd:        1 byte (len itself)
    ///   len <= 0xffff:     0xfd + 2 bytes LE                (3 bytes)
    ///   len <= 0xffffffff: 0xfe + 4 bytes LE                (5 bytes)
    ///   otherwise:         0xff + 8 bytes LE                (9 bytes — never used in
    ///                                                        practice for BSV scripts)
    ///
    /// We must support all four shapes; emitting a 3-byte varint for a script whose
    /// length exceeds 0xffff produces a truncated value that no longer matches what
    /// the BSV node uses for hashOutputs, breaking the state-continuation hash
    /// equality assertion downstream. (This is the second of the two bugs fixed
    /// alongside `parse_variable_length_state_fields`'s varint stripping — see
    /// `integration/go/contracts/RollupBug.runar.go`.)
    ///
    /// OP_NUM2BIN uses sign-magnitude encoding where high-bit values need an extra
    /// sign byte; we generate one extra byte and then SPLIT off the unsigned low
    /// bytes to get the correct unsigned varint payload.
    fn emit_varint_encoding(&mut self) {
        // Stack: [..., script, len]

        // emit_num_to_low_bytes: [..., len] -> [..., low_n_bytes]. Uses
        // NUM2BIN(n+1) then SPLIT(n) DROP to drop the sign byte.
        fn emit_num_to_low_bytes(ctx: &mut LoweringContext, n_bytes: i128) {
            ctx.emit_op(StackOp::Push(PushValue::Int(BigInt::from(n_bytes + 1))));
            ctx.sm.push("");
            ctx.emit_op(StackOp::Opcode("OP_NUM2BIN".into()));
            ctx.sm.pop();
            ctx.sm.pop();
            ctx.sm.push("");
            ctx.emit_op(StackOp::Push(PushValue::Int(BigInt::from(n_bytes))));
            ctx.sm.push("");
            ctx.emit_op(StackOp::Opcode("OP_SPLIT".into()));
            ctx.sm.pop();
            ctx.sm.pop();
            ctx.sm.push("");
            ctx.sm.push("");
            ctx.emit_op(StackOp::Drop);
            ctx.sm.pop();
        }

        // emit_prefix: [..., script, low_bytes] -> [..., script, prefix||low_bytes].
        fn emit_prefix(ctx: &mut LoweringContext, prefix_byte: u8) {
            ctx.emit_op(StackOp::Push(PushValue::Bytes(vec![prefix_byte])));
            ctx.sm.push("");
            ctx.emit_op(StackOp::Swap);
            ctx.sm.swap();
            ctx.sm.pop();
            ctx.sm.pop();
            ctx.emit_op(StackOp::Opcode("OP_CAT".into()));
            ctx.sm.push("");
        }

        // IF len < 253: 1-byte varint.
        self.emit_op(StackOp::Dup);
        self.sm.dup();
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(253))));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_LESSTHAN".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_IF".into()));
        self.sm.pop();
        let sm_at_1_byte = self.sm.clone();
        emit_num_to_low_bytes(self, 1);
        self.emit_op(StackOp::Opcode("OP_ELSE".into()));
        self.sm = sm_at_1_byte.clone();

        // ELSE-IF len <= 0xffff: 0xfd + 2-byte LE.
        self.emit_op(StackOp::Dup);
        self.sm.dup();
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(0x10000i64))));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_LESSTHAN".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_IF".into()));
        self.sm.pop();
        let sm_at_3_byte = self.sm.clone();
        emit_num_to_low_bytes(self, 2);
        emit_prefix(self, 0xfd);
        self.emit_op(StackOp::Opcode("OP_ELSE".into()));
        self.sm = sm_at_3_byte.clone();

        // ELSE-IF len <= 0xffffffff: 0xfe + 4-byte LE.
        self.emit_op(StackOp::Dup);
        self.sm.dup();
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(0x100000000i64))));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_LESSTHAN".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_IF".into()));
        self.sm.pop();
        let sm_at_5_byte = self.sm.clone();
        emit_num_to_low_bytes(self, 4);
        emit_prefix(self, 0xfe);
        self.emit_op(StackOp::Opcode("OP_ELSE".into()));
        self.sm = sm_at_5_byte.clone();

        // ELSE: 0xff + 8-byte LE. (>= 4 GiB script — practically unreachable on
        // BSV but kept for spec completeness so we never silently truncate.)
        emit_num_to_low_bytes(self, 8);
        emit_prefix(self, 0xff);

        self.emit_op(StackOp::Opcode("OP_ENDIF".into()));
        self.emit_op(StackOp::Opcode("OP_ENDIF".into()));
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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(76))));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_LESSTHAN".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_IF".into()));
        self.sm.pop();
        let sm_after_outer_if = self.sm.clone();

        // THEN: len <= 75
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(2))));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(1))));
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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(256))));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_LESSTHAN".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_IF".into()));
        self.sm.pop();
        let sm_after_inner_if = self.sm.clone();

        // THEN: 76-255 → 0x4c + 1-byte
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(2))));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(1))));
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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(4))));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(2))));
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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(1))));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push(""); self.sm.push("");
        self.emit_op(StackOp::Swap); self.sm.swap();
        self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
        self.emit_op(StackOp::Dup);
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(76))));
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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(77))));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUMEQUAL".into()));
        self.sm.pop(); self.sm.pop();
        self.sm.push("");

        self.emit_op(StackOp::Opcode("OP_IF".into()));
        self.sm.pop();
        let sm_after_inner_if = self.sm.clone();

        // THEN: fb == 77 → 2-byte LE
        self.emit_op(StackOp::Drop); self.sm.pop();
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(2))));
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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(1))));
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

    /// Consume-vs-copy decision for one operand of a multi-operand ANF value.
    ///
    /// `operands` is the FULL operand-ref list of the value (including
    /// `operand_ref` itself). The load may consume (ROLL / move) the ref only
    /// when this binding is the ref's last use AND the ref occurs exactly
    /// once in the operand list. A ref that is read at more than one operand
    /// position of the same value must be copied (PICK / DUP) at EVERY
    /// position: each operand position needs its own stack slot, and a
    /// consume-mode load of a ref that is already on top of the stack is a
    /// no-op (see `bring_to_top`), so two consume-mode loads of the same ref
    /// would leave a single slot for an opcode that pops one item per operand
    /// (e.g. `t := x + x` underflowing OP_ADD), or — when the ref sits below
    /// other live slots — silently pair the opcode with the wrong slot. The
    /// original value then simply stays on the stack, exactly like any ref
    /// whose last use is a later binding.
    ///
    /// Unreachable from the frontend (ANF lowering gives every operand a
    /// fresh temp); reachable via `compile_from_ir` / CLI `--ir` hand-written
    /// ANF.
    fn operand_consume<S: AsRef<str>>(
        &self,
        operand_ref: &str,
        operands: &[S],
        current_index: usize,
        last_uses: &HashMap<String, usize>,
    ) -> bool {
        if !self.is_last_use(operand_ref, current_index, last_uses) {
            return false;
        }
        operands.iter().filter(|o| o.as_ref() == operand_ref).count() <= 1
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(depth as i128))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(depth as i128))));
                self.sm.push(""); // temporary
                self.emit_op(StackOp::Pick { depth });
                self.sm.pop(); // remove depth literal
                let picked = self.sm.peek_at_depth(depth).to_string();
                self.sm.push(&picked);
            }
        }

        self.track_depth();
    }

    /// Drain branch-private residue from below TOS at the end of a branch
    /// body, so both branches converge to a layout the parent stack model can
    /// faithfully describe before OP_ENDIF (issue #36).
    ///
    /// A slot is residue when its name is NOT in `pre_if_names` (the snapshot
    /// of the parent's named slots taken before the branch ran). This catches
    /// both anonymous slots (empty-named, pushed by intrinsics like substr's
    /// OP_SPLIT residue) and named branch-local bindings that lingered past
    /// their last-use (e.g. dead-code load_const intermediates the optimizer
    /// didn't fold).
    ///
    /// Slots whose name was already in `pre_if_names` are kept — including
    /// duplicates created by reassigning an outer-scope local from inside the
    /// branch. The TOS slot is also kept regardless.
    /// Physically remove the stack slot `depth` places below the top.
    fn drop_slot_at_depth(&mut self, depth: usize) {
        if depth == 0 {
            self.emit_op(StackOp::Drop);
            self.sm.pop();
            return;
        }
        if depth == 1 {
            self.emit_op(StackOp::Nip);
            self.sm.remove_at_depth(1);
            return;
        }
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(depth as i128))));
        self.sm.push("");
        self.emit_op(StackOp::Roll { depth });
        self.sm.pop();
        let rolled = self.sm.remove_at_depth(depth);
        self.sm.push(&rolled);
        self.emit_op(StackOp::Drop);
        self.sm.pop();
    }

    fn drain_branch_private_residue(&mut self, pre_if_names: &HashSet<String>) {
        let mut drain_depths: Vec<usize> = Vec::new();
        for d in 1..self.sm.depth() {
            let name = self.sm.peek_at_depth(d);
            if name.is_empty() {
                drain_depths.push(d);
            } else if !pre_if_names.contains(name) {
                drain_depths.push(d);
            }
        }
        if drain_depths.is_empty() {
            return;
        }
        drain_depths.sort_by(|a, b| b.cmp(a));
        for depth in drain_depths {
            if depth == 1 {
                self.emit_op(StackOp::Nip);
                self.sm.remove_at_depth(1);
            } else {
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(depth as i128))));
                self.sm.push("");
                self.emit_op(StackOp::Roll { depth });
                self.sm.pop();
                let rolled = self.sm.remove_at_depth(depth);
                self.sm.push(&rolled);
                self.emit_op(StackOp::Drop);
                self.sm.pop();
            }
        }
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
            // Propagate source location from ANF binding to StackOps
            self.current_source_loc = binding.source_loc.clone();

            if matches!(&binding.value, ANFValue::Assert { .. }) && i as isize == last_assert_idx {
                // Terminal assert: leave value on stack instead of OP_VERIFY
                if let ANFValue::Assert { value, .. } = &binding.value {
                    self.lower_assert(value, i, &last_uses, true);
                }
            } else if matches!(&binding.value, ANFValue::If { .. }) && i as isize == terminal_if_idx {
                // Terminal if: propagate terminalAssert into both branches
                if let ANFValue::If { cond, then, else_branch, results } = &binding.value {
                    self.lower_if(&binding.name, cond, then, else_branch, results, i, &last_uses, true);
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
                results,
            } => {
                self.lower_if(name, cond, then, else_branch, results, binding_index, last_uses, false);
            }
            ANFValue::Loop {
                count,
                body,
                iter_var,
                start,
                step,
            } => {
                self.lower_loop(name, *count, body, iter_var, start, *step, Some(binding_index), Some(last_uses));
            }
            ANFValue::Assert { value, .. } => {
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
            ANFValue::CheckPreimage { preimage, sighash_flag } => {
                self.lower_check_preimage(name, preimage, *sighash_flag, binding_index, last_uses);
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
            ANFValue::AddDataOutput { satoshis, script_bytes } => {
                // Wire shape matches add_raw_output: amount(8LE) + varint(scriptLen) + scriptBytes.
                // The distinction lives in the continuation-hash composition (ANF lowering).
                self.lower_add_raw_output(name, satoshis, script_bytes, binding_index, last_uses);
            }
            ANFValue::ArrayLiteral { elements } => {
                self.lower_array_literal(name, elements, binding_index, last_uses);
            }
            ANFValue::RawScript { bytes, in_arity, out_arity } => {
                self.lower_raw_script(name, bytes, *in_arity, *out_arity);
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
        // The parameter is on the stack under its original name — or, for a
        // param that shadows a mutable property, under a reserved renamed slot
        // (issue #130) so it is not confused with the deserialized property
        // slot.
        let slot_name = self
            .renamed_params
            .get(param_name)
            .cloned()
            .unwrap_or_else(|| param_name.to_string());
        if self.sm.has(&slot_name) {
            let is_last = self.is_last_use(param_name, binding_index, last_uses);
            self.bring_to_top(&slot_name, is_last);
            self.sm.pop();
            self.sm.push(binding_name);
        } else {
            // Parameter no longer on the stack — a compiler invariant violation
            // (historically caused by unrolled loops consuming outer refs; see
            // lower_loop). Silently emitting OP_0 here produced scripts that
            // compiled, passed the env-based interpreter, and then failed on
            // chain — fail loudly instead.
            panic!(
                "Stack lowering: method parameter '{}' is not on the stack at a \
                 post-consumption reference (stack: [{}]). Refusing to emit a \
                 silent OP_0 placeholder.",
                param_name,
                self.sm.debug_slots()
            );
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
                let param_index = self.ctor_param_index_or_panic(prop_name);
                self.emit_op(StackOp::Placeholder {
                    param_index,
                    param_name: prop_name.to_string(),
                });
            }
        } else {
            // Property not found and not on stack — must still be a real
            // constructor-param slot, otherwise there is nothing to splice.
            let param_index = self.ctor_param_index_or_panic(prop_name);
            self.emit_op(StackOp::Placeholder {
                param_index,
                param_name: prop_name.to_string(),
            });
        }
        self.sm.push(binding_name);
    }

    /// Resolve `prop_name`'s constructor slot for a placeholder, or fail loudly.
    ///
    /// #119 tail (H1): a property that reaches the placeholder fallback with no
    /// matching constructor slot has no deploy-time bytes of its own. The
    /// previous behaviour coerced it onto slot 0 (`.unwrap_or(0)`), silently
    /// splicing an UNRELATED constructor argument's placeholder into the
    /// locking script — a silent-wrong-code path. Fail loudly instead. (A real
    /// constructor-param property — readonly, or a mutable state field whose
    /// initial value is spliced at deploy — is found by `position` and is
    /// unaffected: zero golden churn.)
    fn ctor_param_index_or_panic(&self, prop_name: &str) -> usize {
        // Initialized properties are excluded from the constructor, so only
        // uninitialized (deploy-time) properties own a constructor slot.
        match self
            .properties
            .iter()
            .filter(|p| p.initial_value.is_none())
            .position(|p| p.name == prop_name)
        {
            Some(idx) => idx,
            None => {
                let loc = self
                    .current_source_loc
                    .as_ref()
                    .map(|l| format!(" at {}:{}:{}", l.file, l.line, l.column))
                    .unwrap_or_default();
                let ctor_props: Vec<&str> = self
                    .properties
                    .iter()
                    .filter(|p| p.initial_value.is_none())
                    .map(|p| p.name.as_str())
                    .collect();
                panic!(
                    "Stack lowering: property '{}'{} is neither on the stack, \
                     initialized, nor a constructor parameter, so it has no \
                     deploy-time slot. Refusing to emit a placeholder for an \
                     unrelated constructor argument (slot 0). Known \
                     constructor-param properties: [{}].",
                    prop_name,
                    loc,
                    ctor_props.join(", ")
                );
            }
        }
    }

    fn push_json_value(&mut self, val: &serde_json::Value) {
        match val {
            serde_json::Value::Bool(b) => {
                self.emit_op(StackOp::Push(PushValue::Bool(*b)));
            }
            serde_json::Value::Number(n) => {
                let i = n.as_i64().map(|v| v as i128).unwrap_or(0);
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(i))));
            }
            serde_json::Value::String(s) => {
                let bytes = hex_to_bytes(s);
                self.emit_op(StackOp::Push(PushValue::Bytes(bytes)));
            }
            _ => {
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(0))));
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
                // Special case: aliasing an array_literal (metadata-only
                // binding, not present in the stack-map). Copy the array
                // metadata under the new binding name and emit no stack moves.
                if let Some(refs) = self.array_elements.get(ref_name).cloned() {
                    self.array_elements.insert(binding_name.to_string(), refs);
                    if let Some(len) = self.array_lengths.get(ref_name).copied() {
                        self.array_lengths.insert(binding_name.to_string(), len);
                    }
                    return;
                }
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
                    // Referenced value no longer on the stack — a compiler
                    // invariant violation (see lower_load_param for the loop-
                    // consumption history). Fail loudly instead of silently
                    // emitting OP_0.
                    panic!(
                        "Stack lowering: value '{}' referenced by '{}' is not on the \
                         stack (stack: [{}]). Refusing to emit a silent OP_0 placeholder.",
                        ref_name,
                        binding_name,
                        self.sm.debug_slots()
                    );
                }
                return;
            }
            // Handle @this marker -- compile-time concept, not a runtime value
            if s == "@this" {
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(0))));
                self.sm.push(binding_name);
                return;
            }
        }

        let cv = value.const_value();
        match &cv {
            Some(ConstValue::Bool(b)) => {
                self.emit_op(StackOp::Push(PushValue::Bool(*b)));
            }
            Some(ConstValue::Int(n)) => {
                self.emit_op(StackOp::Push(PushValue::Int(n.clone())));
            }
            Some(ConstValue::Str(s)) => {
                let bytes = hex_to_bytes(s);
                self.emit_op(StackOp::Push(PushValue::Bytes(bytes)));
            }
            None => {
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(0))));
            }
        }
        // Track constant values for compile-time extraction (e.g., Merkle depth)
        if let Some(c) = cv {
            self.const_values.insert(binding_name.to_string(), c);
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
        let left_consume = self.operand_consume(left, &[left, right], binding_index, last_uses);
        self.bring_to_top(left, left_consume);

        let right_consume = self.operand_consume(right, &[left, right], binding_index, last_uses);
        self.bring_to_top(right, right_consume);

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

        // exit(condition) => condition OP_VERIFY — same as assert
        if func_name == "exit" {
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

        if is_nist_ec_builtin(func_name) {
            self.lower_nist_ec_builtin(binding_name, func_name, args, binding_index, last_uses);
            return;
        }

        if func_name == "verifyECDSA_P256" || func_name == "verifyECDSA_P384" {
            self.lower_verify_ecdsa(binding_name, func_name, args, binding_index, last_uses);
            return;
        }

        if is_bb_builtin(func_name) {
            self.lower_bb_field_builtin(binding_name, func_name, args, binding_index, last_uses);
            return;
        }

        if is_kb_builtin(func_name) {
            self.lower_kb_field_builtin(binding_name, func_name, args, binding_index, last_uses);
            return;
        }

        if is_bn254_builtin(func_name) {
            self.lower_bn254_builtin(binding_name, func_name, args, binding_index, last_uses);
            return;
        }

        if is_merkle_builtin(func_name) {
            self.lower_merkle_root(binding_name, func_name, args, binding_index, last_uses);
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
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
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
            self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(0))));
            self.sm.push(binding_name);
            return;
        }

        if func_name == "split" {
            self.sm.push("");
            self.sm.push(binding_name);
        } else if func_name == "len" {
            // OP_SIZE leaves original on stack and pushes length on top.
            // Emit OP_NIP to remove the original value, keeping only the size.
            self.emit_op(StackOp::Opcode("OP_NIP".to_string()));
            self.sm.push(binding_name); // size only
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
                let consume = self.operand_consume(arg, args, binding_index, last_uses);
                self.bring_to_top(arg, consume);
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
        // `results` is the `if` node's declared result slots, deepest first
        // (see `ANFValue::If::results`). Empty for an `if` that carries at most
        // one result, and then every path below behaves exactly as it did
        // before the multi-result contract existed.
        results: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
        terminal_assert: bool,
    ) {
        // The ANF wire format has no version field, and `--ir` / `--ir-parity`
        // are documented surfaces that feed a checked-in ANF JSON straight into
        // this pass. An ANF produced BEFORE the multi-result node carries the
        // trailing `__merge$` block WITHOUT `results` — back then the block was
        // a naming CONVENTION this pass recognised, and no tier recognises it
        // any more. It deserialises cleanly, the declared count is 0, and the
        // result count falls back to `then_depth - parent_depth`, which counts
        // the arm's untrimmed block residue as results. Refuse it: the block can
        // only be emitted by `append_branch_results`, which only runs for an
        // `if` that declares `results`. Emits no opcodes.
        if results.is_empty() {
            if let Some(stale) = then_bindings
                .iter()
                .chain(else_bindings.iter())
                .find(|b| b.name.starts_with(MERGED_LOCAL_TEMP_PREFIX))
            {
                panic!(
                    "ANF produced by a pre-multi-result compiler: the conditional's \
                     arm carries a '{}' block but the node declares no results \
                     (binding '{}'). That block used to be a naming convention this \
                     pass inferred results from; it is now a declared contract, and \
                     no tier reads the convention any more. Recompile the source \
                     with the current compiler instead of reusing the stored ANF. \
                     binding='{}'.",
                    MERGED_LOCAL_TEMP_PREFIX, stale.name, binding_name
                );
            }
        }

        // Result slots are identified BY NAME — two identically-named results
        // are indistinguishable, so the layout assertion would be satisfied by
        // coincidence while one value silently replaced the other. ANF lowering
        // refuses the source shape; this guards the `--ir` path, where the list
        // arrives as data.
        if results.len() > 1 {
            let unique: HashSet<&String> = results.iter().collect();
            if unique.len() != results.len() {
                panic!(
                    "Internal codegen error: the conditional declares duplicate \
                     result names [{}]. Result slots are matched by name, so \
                     duplicates cannot be told apart and one value would silently \
                     replace the other. binding='{}'.",
                    results.join(", "),
                    binding_name
                );
            }
        }

        // NEW-015: does an ARM read the condition again?
        //
        // `last_uses` is keyed by the index of the ENCLOSING binding, and
        // `collect_refs` deliberately recurses into `then` / `else` so an
        // arm-only ref is not dropped early. Both facts together mean an arm's
        // read of the condition lands on THIS binding's index —
        // indistinguishable from a ref used only as the condition.
        // `is_last_use` then said "yes, consume it", `bring_to_top` ROLLed the
        // slot away, and the arm looked for a value that was no longer there:
        //
        //     let f: boolean = c > 0n;
        //     assert(f ? c > 10n : !f);
        //     //  Value 'f' not found on stack (stack has 1 items: [c])
        //
        // Legal source, accepted by validate and typecheck, rejected here — so
        // there was no diagnostic a developer could act on. It only ever bit
        // when the condition local was DEAD after the `if`; one that stayed
        // live was already covered by the `last_idx > binding_index` rule
        // below, which is why the shape looked like it worked. `&&` / `||`
        // desugar to this node, so `f || !f` routes through the same path.
        let cond_read_in_arms = then_bindings
            .iter()
            .chain(else_bindings.iter())
            .any(|b| collect_refs(&b.value).iter().any(|r| r == cond));

        let is_last = !cond_read_in_arms && self.is_last_use(cond, binding_index, last_uses);
        self.bring_to_top(cond, is_last);
        self.sm.pop(); // OP_IF consumes condition

        // Identify parent-scope items still needed after this if-expression.
        let mut protected_refs = HashSet::new();
        for (ref_name, &last_idx) in last_uses.iter() {
            if last_idx > binding_index && self.sm.has(ref_name) {
                protected_refs.insert(ref_name.clone());
            }
        }

        // A condition the arms re-read was PICKed just above, so the slot
        // survived OP_IF. Protect it for the same reason the merged-local block
        // below is protected: only ONE arm may hold the read, so letting that
        // arm consume the slot would leave the two arms at different depths
        // over a name the parent still models.
        if cond_read_in_arms && self.sm.has(cond) {
            protected_refs.insert(cond.to_string());
        }

        // The K>=2 merged-local block reads every merged local in BOTH arms,
        // and that read is RECONCILIATION, not a use: it is what makes each arm
        // leave exactly K equally-named result slots for the N>=2 reconcile
        // below to adopt. So the merged locals must be copied, never consumed —
        // regardless of whether the ENCLOSING scope reads them again.
        //
        // `append_merged_local_results` (ANF lowering) states that as its
        // premise: "pass 1 always COPIES ... because a local live after the
        // `if` is in `outer_protected_refs`". Enclosing-scope liveness is the
        // wrong question, and the premise silently failed for every merged
        // local whose last enclosing use IS this `if` — which is EVERY merged
        // local of an `if` in a loop body, since the body's last-use map ends
        // at the `if` itself.
        //
        // What happened then: pass 1 ROLLED instead of picking, the arm's stack
        // effect stopped being +K, the arms ended at different depths, phase 3
        // padded the shortfall with EMPTY pushes, the N-result layout check saw
        // an unnamed slot where it needed the merged name, and control fell
        // through to the single-slot fallback `push(binding_name)` — ONE
        // stackMap name registered for K physical results, with `acc`/`wacc`
        // still naming the dead pre-`if` slots.
        // `for (i<2) { if (i<5) { acc = acc + step; wacc = wacc + acc; } }`
        // with step = 3 produced wacc = 3 where the source says 9: silently in
        // a stateless contract, and as a permanently unspendable UTXO in a
        // stateful one.
        //
        // Byte-neutral for every program whose merged locals were already live
        // after the `if`: those names are already protected above, which is
        // precisely why those programs compiled correctly.
        //
        // Now driven by the node's DECLARED results instead of by recognising a
        // trailing `__merge$` block, so an arm-written property is protected on
        // the same footing as a rebound local.
        for name in results {
            if self.sm.has(name) {
                protected_refs.insert(name.clone());
            }
        }

        // Snapshot parent stackMap names before branches run
        let pre_if_names = self.sm.named_slots();

        // Lower then-branch
        let mut then_ctx = LoweringContext::new(&[], &self.properties);
        // Inherit the EXPERIMENTAL EC size options: branch-guarded crypto lives
        // in the arms, so dropping them here made the flags a no-op for exactly
        // the shape that needs them — and diverged from Java/Zig, which inherit.
        then_ctx.ec_codegen = self.ec_codegen;
        then_ctx.sm = self.sm.clone();
        then_ctx.outer_protected_refs = Some(protected_refs.clone());
        then_ctx.inside_branch = true;
        then_ctx.lower_bindings(then_bindings, terminal_assert);

        then_ctx.drain_branch_private_residue(&pre_if_names);

        if terminal_assert && then_ctx.sm.depth() > 1 {
            let excess = then_ctx.sm.depth() - 1;
            for _ in 0..excess {
                then_ctx.emit_op(StackOp::Nip);
                then_ctx.sm.remove_at_depth(1);
            }
        }

        // Lower else-branch
        let mut else_ctx = LoweringContext::new(&[], &self.properties);
        // Inherit the EXPERIMENTAL EC size options: branch-guarded crypto lives
        // in the arms, so dropping them here made the flags a no-op for exactly
        // the shape that needs them — and diverged from Java/Zig, which inherit.
        else_ctx.ec_codegen = self.ec_codegen;
        else_ctx.sm = self.sm.clone();
        else_ctx.outer_protected_refs = Some(protected_refs);
        else_ctx.inside_branch = true;
        else_ctx.lower_bindings(else_bindings, terminal_assert);

        else_ctx.drain_branch_private_residue(&pre_if_names);

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
        //
        // NEW-018: counted by MULTIPLICITY, not by name-set membership.
        //
        // A parent stack legitimately holds the same name in more than one slot
        // — a loop rebinding a local leaves one slot per unrolled iteration, all
        // named `acc`, of which only the shallowest is ever read (the model
        // resolves a name to its shallowest slot). When an arm ROLLs that live
        // slot away, the name is STILL in the arm's name SET because the dead
        // residue slot beneath it carries the same name — so the set-difference
        // this phase used to compute saw nothing consumed, emitted no matching
        // drop in the sibling, and left the two arms one slot apart.
        //
        // Phase 3 then "fixed" the depth with an anonymous pad. A pad restores
        // the COUNT but not the POSITION: the arm that lost a slot from the
        // middle of the region gets a placeholder next to its result, while the
        // sibling still holds the real value in the original slot. The two arms
        // leave positionally different stacks, the parent adopts one of them,
        // and every slot the other arm holds below the result is off by one:
        //
        //     let acc = p; let wacc = 0n;
        //     for (…) for (…) { acc = acc + p; wacc = wacc + acc; }
        //     let br0 = 0n; const sib0 = p;
        //     if (p === 0n) { br0 = p; }
        //     assert((p >= 0n ? acc >= 0n : false) ? (br0 < sib0) : false);
        //
        // The inner conditional is the CONDITION of the outer one. Its then-arm
        // consumes the live `acc`; the parent holds `acc` twice, so phase 1
        // missed it and the arms came back as `[t · br0 sib0 …]` against
        // `[t br0 sib0 acc …]`. With p = 1 the source ACCEPTS and the AST
        // interpreter accepts; the script engines reject the spend with "The top
        // stack element must be truthy after script evaluation" — an ordinary
        // contract deployed to a permanently unspendable UTXO. It needs no `&&`:
        // a plain nested ternary reaches it, and `a && b && c` is
        // left-associative, so it is also what blocked the short-circuit
        // desugar.
        //
        // Counting occurrences instead makes the sibling drop its matching slot,
        // both arms end at the same depth with the same layout, and no pad is
        // needed at all. Byte-neutral for every parent stack with no duplicated
        // name: for a name held once, "parent has 1, arm has 0" is exactly the
        // old `!post_then_names.contains(name)`, and the drop depths are the
        // same list.
        let pre_if_counts = self.sm.name_counts();
        let then_counts = then_ctx.sm.name_counts();
        let else_counts = else_ctx.sm.name_counts();
        let mut consumed_names: Vec<String> = Vec::new();
        let mut else_consumed_names: Vec<String> = Vec::new();
        // Iterate the parent's slots, not the count map, so the result order is
        // deterministic — `HashMap` iteration order is not.
        let mut seen: HashSet<&str> = HashSet::new();
        for i in 0..self.sm.depth() {
            let name = self.sm.peek_at_depth(i);
            if name.is_empty() || !seen.insert(name) {
                continue;
            }
            let held = *pre_if_counts.get(name).unwrap_or(&0);
            let then_lost = held.saturating_sub(*then_counts.get(name).unwrap_or(&0));
            let else_lost = held.saturating_sub(*else_counts.get(name).unwrap_or(&0));
            for _ in 0..then_lost.saturating_sub(else_lost) {
                consumed_names.push(name.to_string());
            }
            for _ in 0..else_lost.saturating_sub(then_lost) {
                else_consumed_names.push(name.to_string());
            }
        }

        // Phase 2: perform ALL drops before any placeholder pushes.
        // This prevents double-placeholder when bilateral drops balance each other.
        if !consumed_names.is_empty() {
            let depths: Vec<usize> = else_ctx.sm.drop_depths_for(&consumed_names);
            for depth in depths {
                if depth == 0 {
                    else_ctx.emit_op(StackOp::Drop);
                    else_ctx.sm.pop();
                } else if depth == 1 {
                    else_ctx.emit_op(StackOp::Nip);
                    else_ctx.sm.remove_at_depth(1);
                } else {
                    else_ctx.emit_op(StackOp::Push(PushValue::Int(BigInt::from(depth as i128))));
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
            let depths: Vec<usize> = then_ctx.sm.drop_depths_for(&else_consumed_names);
            for depth in depths {
                if depth == 0 {
                    then_ctx.emit_op(StackOp::Drop);
                    then_ctx.sm.pop();
                } else if depth == 1 {
                    then_ctx.emit_op(StackOp::Nip);
                    then_ctx.sm.remove_at_depth(1);
                } else {
                    then_ctx.emit_op(StackOp::Push(PushValue::Int(BigInt::from(depth as i128))));
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

        // Trim each arm down to exactly its declared result slots.
        //
        // ANF lowering ends both arms with an identical N-binding block that
        // rebinds every declared result from a `__merge$<i>` temp (see
        // `append_branch_results`). That block leaves the N live values on top
        // in the same canonical order in both arms — but BENEATH them each arm
        // still holds whatever its own body produced, and those differ per arm.
        // Everything beneath the N results is dead: the block copied each
        // result before rebinding it, and a branch-local binding is not visible
        // after the `if`.
        //
        // Runs AFTER the phase-2 consumption drops, so both arms have given up
        // the same parent slots and share one base depth.
        //
        // NEW-018: counted by MULTIPLICITY, for the same reason phase 1 is.
        // Phase 1 now makes both arms give up the same slot of a name the parent
        // holds twice, so the base depth has to count that slot as given up too
        // — otherwise `target_depth` is one too high, the trim below does
        // nothing, and the layout assertion fires on a well-formed program.
        let n_declared = results.len();
        if n_declared >= 1 {
            let still_held_counts = then_ctx.sm.name_counts();
            let consumed_from_parent: usize = pre_if_counts
                .iter()
                .map(|(name, held)| held.saturating_sub(*still_held_counts.get(name).unwrap_or(&0)))
                .sum();
            let target_depth = self.sm.depth() - consumed_from_parent + n_declared;
            for arm_ctx in [&mut then_ctx, &mut else_ctx] {
                while arm_ctx.sm.depth() > target_depth {
                    arm_ctx.drop_slot_at_depth(n_declared);
                }
            }

            // The declared contract, checked rather than assumed: after the
            // trim, each arm's top N slots must BE the declared results, in the
            // declared order (`results[0]` deepest). `append_branch_results` is
            // what makes this true; if it ever stops being true the arms
            // disagree on layout, which is precisely the failure that produced
            // the 2026-08 miscompile family. Emits no opcodes.
            for (label, arm_ctx) in [("then", &then_ctx), ("else", &else_ctx)] {
                if arm_ctx.sm.depth() != target_depth {
                    panic!(
                        "internal codegen error: branch result layout mismatch — the {}-arm of the conditional ends at depth {}, but its {} declared result(s) require depth {}; binding={:?}",
                        label, arm_ctx.sm.depth(), n_declared, target_depth, binding_name
                    );
                }
                for i in 0..n_declared {
                    let want = &results[n_declared - 1 - i];
                    let got = arm_ctx.sm.peek_at_depth(i);
                    if got != want.as_str() {
                        panic!(
                            "internal codegen error: branch result layout mismatch — the {}-arm of the conditional holds {:?} where the node declares {:?} (slot {} of [{}]); every later operand would resolve to the wrong slot; binding={:?}",
                            label, got, want, n_declared - 1 - i, results.join(", "), binding_name
                        );
                    }
                }
            }
        }

        // Phase 3: depth-balance reconciliation after ALL drops.
        //
        // Compensate the FULL depth difference between the branches — NOT just a
        // single item. A conditional write of N state fields leaves N result
        // values on the then-branch, so the (empty) else-branch must preserve N
        // old values. Issue #99 Bug 1: the previous single-shot check only
        // balanced a 1-item difference, leaving N>=2 conditional writes
        // imbalanced by (N-1) and the update branch unspendable.
        while then_ctx.sm.depth() > else_ctx.sm.depth() {
            let result_depth = then_ctx.sm.depth() - else_ctx.sm.depth() - 1;
            let then_name = then_ctx.sm.peek_at_depth(result_depth).to_string();
            if else_bindings.is_empty() && !then_name.is_empty() && else_ctx.sm.has(&then_name) {
                let var_depth = else_ctx.sm.find_depth(&then_name).unwrap();
                if var_depth == 0 {
                    else_ctx.emit_op(StackOp::Dup);
                } else {
                    else_ctx.emit_op(StackOp::Push(PushValue::Int(BigInt::from(var_depth as i128))));
                    else_ctx.sm.push("");
                    else_ctx.emit_op(StackOp::Pick { depth: var_depth });
                    else_ctx.sm.pop();
                }
                else_ctx.sm.push(&then_name);
            } else {
                else_ctx.emit_op(StackOp::Push(PushValue::Bytes(Vec::new())));
                else_ctx.sm.push("");
            }
        }
        while else_ctx.sm.depth() > then_ctx.sm.depth() {
            then_ctx.emit_op(StackOp::Push(PushValue::Bytes(Vec::new())));
            then_ctx.sm.push("");
        }

        // Layer B — branch-balance invariant (#99 Bug 1 guard). After
        // reconciliation the two arms of an OP_IF/OP_ELSE MUST leave the stack
        // at identical depth; otherwise the post-ENDIF code (generated against a
        // single assumed depth) is only correct for the branch the spender does
        // not take, producing a silently-unspendable script. The VM does not
        // enforce branch balance, so this is the compiler's responsibility.
        if then_ctx.sm.depth() != else_ctx.sm.depth() {
            panic!(
                "internal codegen error: conditional emitted stack-imbalanced branches (then depth {} != else depth {}); would produce an unspendable script (see GitHub issue #99); binding={:?}",
                then_ctx.sm.depth(),
                else_ctx.sm.depth(),
                binding_name
            );
        }

        // NEW-018 needs the arms' post-branch name MULTISET. Snapshotted here
        // because the arms' op lists are consumed immediately after this point.
        let post_branch_counts = then_ctx.sm.name_counts();

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

        // Physical slots this function drops AFTER OP_ENDIF, while reconciling
        // the parent stackMap against the arms' results. Counted because the
        // invariant at the end of `lower_if` cannot compare the two depths
        // directly: the post-ENDIF reconcile legitimately ROLL/DROPs stale slots
        // out from under the results, so those drops have to be added back
        // before comparing.
        let mut post_endif_drops = 0usize;

        // Reconcile parent stackMap: remove items consumed by the branches.
        //
        // NEW-018: counted by MULTIPLICITY, for the same reason phase 1 is. When
        // the arms consume the live slot of a name the parent holds twice, the
        // parent must give up one slot too — the set test kept both, so the
        // parent modelled one more slot than the arms physically left and the
        // adopt below saw `arm_depth == parent_depth` and pushed nothing at all.
        for (name, held) in &pre_if_counts {
            let mut excess = held.saturating_sub(*post_branch_counts.get(name).unwrap_or(&0));
            while excess > 0 && self.sm.has(name) {
                if let Some(depth) = self.sm.find_depth(name) {
                    self.sm.remove_at_depth(depth);
                }
                excess -= 1;
            }
        }

        // C27: the N>=2 result reconcile below also applies when the else-branch
        // is PRESENT and BOTH arms wrote the same N mutable fields (e.g. each
        // branch runs `this.a = ...; this.b = ...`). This is the else-present twin
        // of the empty-else fix (#99 Bug 1). Without it, lower_if falls through to
        // `push(binding_name)` further down — registering ONE stackMap name for N
        // physical results — so the state serialization emits against the wrong
        // slot (OP_NUM2BIN on a byte string) and the continuation is unspendable (a
        // funds-safety bug). Only fire when both arms leave the identical top-N
        // property names in the identical order, so a single post-ENDIF reconcile
        // is valid regardless of which branch the spender takes. The single-field
        // same-property case (N==1, "turn flip") is unaffected — it still takes the
        // dedicated path below. Empty slot names ("") are treated as "not a match".
        let n_results = then_ctx.sm.depth() as isize - self.sm.depth() as isize;
        let else_matches_then_n_result_layout = !else_bindings.is_empty()
            && n_results >= 2
            && (else_ctx.sm.depth() as isize - self.sm.depth() as isize) == n_results
            && (0..n_results as usize).all(|i| {
                let tn = then_ctx.sm.peek_at_depth(i);
                !tn.is_empty()
                    && tn == else_ctx.sm.peek_at_depth(i)
            });

        // The if expression may produce a result value on top.
        if n_declared >= 1 {
            // DECLARED RESULTS. Both arms were normalised by
            // `append_branch_results` and the layout check above proved they
            // hold exactly `results`, so the parent adopts them BY THE DECLARED
            // ORDER — no counting of trailing `__merge$` bindings, no
            // comparison of arm depths, no inference of which names are still
            // live. `results[0]` is the deepest slot, matching the order pass 2
            // of the normalisation rebound them in.
            //
            // Then each parent slot the block shadows (the pre-`if` binding of
            // a merged local, the stale value of a written property) is
            // physically rolled out from under the results, exactly as the
            // pre-existing N>=2 reconcile did — which is why the four
            // `__merge$` goldens keep their bytes.
            for name in results {
                self.sm.push(name);
            }
            // How far below the result block the deepest stale slot sat.
            // Adopting a result puts it ON TOP, but its pre-`if` binding lived
            // at depth `d`, i.e. BENEATH the `d - n_declared` slots in between.
            // Removing the stale copy does not reorder those in-between slots,
            // so after the loop the adopted result has crossed them: the layout
            // is rotated even though the NAME SET and the DEPTH are both
            // unchanged. That is invisible to the reconcile's name-set check and
            // to the depth check below, and it is the whole of issue #149 — see
            // `sink_below` below.
            let mut sink_below = 0usize;
            for i in (0..n_declared).rev() {
                let name = &results[i];
                let mut d = n_declared;
                while d < self.sm.depth() {
                    if self.sm.peek_at_depth(d) == name.as_str() {
                        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(d as i128))));
                        self.sm.push("");
                        self.emit_op(StackOp::Roll { depth: d + 1 });
                        self.sm.pop();
                        let rolled = self.sm.remove_at_depth(d);
                        self.sm.push(&rolled);
                        self.emit_op(StackOp::Drop);
                        self.sm.pop();
                        post_endif_drops += 1;
                        if d - n_declared > sink_below {
                            sink_below = d - n_declared;
                        }
                        break;
                    }
                    d += 1;
                }
            }

            // Restore the inherited layout: sink the whole result block back
            // under the `sink_below` slots it just crossed, so BOTH paths of the
            // enclosing `if` leave the same slot order and every post-OP_ENDIF
            // read resolves against the layout it was generated for. Rolling the
            // deepest item of the (n_declared + sink_below) window to the top,
            // `sink_below` times, lifts those slots back above the results while
            // preserving their own relative order.
            // Applied unconditionally, NOT gated on this `if`'s own else. The
            // asymmetry that makes #149 unspendable belongs to the ENCLOSING
            // `if` (whose fall-through path keeps the pre-`if` layout), and
            // `lower_if` has no view of its parent here. Gating on
            // `else_bindings.is_empty()` was measured and is WRONG: the #149
            // inner `if` has a real else, so the gate disables the repair
            // exactly where it is needed. Restoring the pre-`if` order
            // unconditionally keeps the parent's own model — names at the depths
            // it recorded before the branch — true on every path.
            if sink_below > 0 {
                let window_size = n_declared + sink_below;
                for _ in 0..sink_below {
                    self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(
                        (window_size - 1) as i128,
                    ))));
                    self.sm.push("");
                    self.emit_op(StackOp::Roll { depth: window_size });
                    self.sm.pop();
                    let lifted = self.sm.remove_at_depth(window_size - 1);
                    self.sm.push(&lifted);
                }
            }
        } else if then_ctx.sm.depth() > self.sm.depth()
            && n_results >= 2
            && (else_bindings.is_empty() || else_matches_then_n_result_layout)
        {
            // #99 Bug 1: a conditional write of N>=2 state fields leaves N result
            // values on top (new values if taken, preserved old values if
            // skipped). Record the N results in their on-stack order, then
            // physically remove the N stale old property values beneath them.
            let result_count = then_ctx.sm.depth() - self.sm.depth();
            for i in (0..result_count).rev() {
                let mut name = then_ctx.sm.peek_at_depth(i).to_string();
                if name.is_empty() {
                    name = binding_name.to_string();
                }
                self.sm.push(&name);
            }
            let result_names: Vec<String> = (0..result_count)
                .map(|i| self.sm.peek_at_depth(i).to_string())
                .collect();
            for name in &result_names {
                if name.is_empty() {
                    continue;
                }
                let mut d = result_count;
                while d < self.sm.depth() {
                    if self.sm.peek_at_depth(d) == name.as_str() {
                        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(d as i128))));
                        self.sm.push("");
                        self.emit_op(StackOp::Roll { depth: d + 1 });
                        self.sm.pop();
                        let rolled = self.sm.remove_at_depth(d);
                        self.sm.push(&rolled);
                        self.emit_op(StackOp::Drop);
                        self.sm.pop();
                        post_endif_drops += 1;
                        break;
                    }
                    d += 1;
                }
            }
        } else if then_ctx.sm.depth() > self.sm.depth() {
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
                            self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(d as i128))));
                            self.sm.push("");
                            self.emit_op(StackOp::Roll { depth: d + 1 });
                            self.sm.pop();
                            let rolled = self.sm.remove_at_depth(d);
                            self.sm.push(&rolled);
                            self.emit_op(StackOp::Drop);
                            self.sm.pop();
                        }
                        post_endif_drops += 1;
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
                            self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(d as i128))));
                            self.sm.push("");
                            self.emit_op(StackOp::Roll { depth: d + 1 });
                            self.sm.pop();
                            let rolled = self.sm.remove_at_depth(d);
                            self.sm.push(&rolled);
                            self.emit_op(StackOp::Drop);
                            self.sm.pop();
                        }
                        post_endif_drops += 1;
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

        // Layer C — branch result-depth invariant.
        //
        // The stackMap is the compiler's ONLY model of the stack, so a stackMap
        // that names FEWER slots than the arms physically left is not detectable
        // anywhere downstream: every later operand silently resolves N slots
        // off. That single failure mode produced the whole 2026-08 branch/loop
        // miscompile family — wrong-but-accepted state continuations at best,
        // and scripts the interpreter rejects outright (locked funds) at worst.
        //
        // What must hold when `lower_if` returns: the parent stackMap describes
        // exactly the physical stack. Both arms ended at `arm_depth` (the
        // branch-balance guard above proves they agree), OP_ENDIF changes
        // nothing, and the only physical effect after it is the
        // `post_endif_drops` stale-slot drops the reconcile emitted. So:
        //
        //     self.sm.depth() + post_endif_drops == arm_depth
        //
        // The naive `self.sm.depth() == arm_depth` is WRONG — the reconcile
        // legitimately ROLL/DROPs stale slots out from under the results, which
        // is exactly what `post_endif_drops` counts.
        //
        // A failure here is always a codegen bug, never a user error. Emits no
        // opcodes: byte-neutral by construction. Same genre as the
        // branch-balance guard (#99), added for the same reason.
        let arm_depth = then_ctx.sm.depth();
        if self.sm.depth() + post_endif_drops != arm_depth {
            panic!(
                "internal codegen error: branch result depth mismatch — the parent stack model does not describe the physical stack after OP_ENDIF (stackMap depth {} + {} post-ENDIF drop(s) != arm depth {}); the arms leave {} more physical slot(s) than the compiler recorded, so every later operand would resolve to the wrong slot and the script would be wrong or unspendable; binding={:?}",
                self.sm.depth(),
                post_endif_drops,
                arm_depth,
                arm_depth as isize - self.sm.depth() as isize - post_endif_drops as isize,
                binding_name
            );
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
        start: &serde_json::Value,
        step: i64,
        loop_binding_index: Option<usize>,
        enclosing_last_uses: Option<&HashMap<String, usize>>,
    ) {
        // Iteration `i` binds `iterVar = start + i*step` (issue #121).
        // Zero-start counting-up loops (start=0, step=1) reduce to `BigInt(i)`,
        // preserving the historical byte-for-byte lowering.
        let start_bigint = match crate::ir::parse_const_value(start) {
            Some(ConstValue::Int(n)) => n,
            _ => BigInt::from(0),
        };
        let step_bigint = BigInt::from(step);
        // Names (re)defined anywhere inside the loop body, nested branches
        // included. A name the body itself binds is NOT an outer ref —
        // reassigned locals (e.g. `off = off + ...` inside an if) flow through
        // lower_if's branch-reassignment reconciliation, not through protection
        // here.
        let deep_body_binding_names = collect_deep_binding_names(body);
        let body_binding_names: HashSet<String> = body.iter().map(|b| b.name.clone()).collect();

        // Collect ALL outer-scope refs used anywhere in the body — including
        // refs that only occur inside nested if-branches (collect_refs recurses).
        // The previous top-level-only scan missed nested references: a const
        // defined before the loop and referenced only inside an if-branch was
        // consumed by the first iteration, making iteration 2 fail with
        // "value 'X' not found on stack".
        let mut outer_refs = HashSet::new();
        for b in body {
            for r in collect_refs(&b.value) {
                if r.as_str() != iter_var && !deep_body_binding_names.contains(&r) {
                    outer_refs.insert(r);
                }
            }
        }

        // A local the body REBINDS and then READS AGAIN in the same iteration
        // is carried across iterations through the rebound slot, so it must
        // survive the body exactly like an outer ref. `deep_body_binding_names`
        // above excludes it precisely because the body binds it — which is what
        // made the updated value consumable. See `collect_loop_carried_rebinds`.
        for r in collect_loop_carried_rebinds(body) {
            if r.as_str() != iter_var {
                outer_refs.insert(r);
            }
        }

        // Temporarily extend localBindings with body binding names so
        // @ref: to body-internal values can consume on last use.
        let prev_local_bindings = self.local_bindings.clone();
        self.local_bindings = self.local_bindings.union(&body_binding_names).cloned().collect();

        for i in 0..count {
            // Push the iteration variable value: start + i*step (issue #121).
            let iter_val = &start_bigint + BigInt::from(i as i128) * &step_bigint;
            self.emit_op(StackOp::Push(PushValue::Int(iter_val)));
            self.sm.push(iter_var);

            let mut last_uses = compute_last_uses(body);

            // Prevent outer-scope refs from being consumed by setting their
            // last-use beyond any body binding index:
            //  - in non-final iterations: always (the next iteration re-reads them);
            //  - in the FINAL iteration: when the enclosing scope still references
            //    them AFTER the loop. Previously the final iteration consumed
            //    every outer ref at its last body use, so a method param (or
            //    const) referenced after the loop was gone from the stack and was
            //    silently lowered to an OP_0/empty push — compilation succeeded,
            //    the env-based interpreter passed, but the emitted Script failed
            //    at runtime (silent interpreter <-> Script divergence).
            let is_final_iteration = i == count - 1;
            for ref_name in &outer_refs {
                let used_after_loop = match (loop_binding_index, enclosing_last_uses) {
                    (Some(idx), Some(elu)) => elu.get(ref_name).map_or(false, |&lu| lu > idx),
                    _ => false,
                };
                if !is_final_iteration || used_after_loop {
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
                        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(d as i128))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(0))));
                self.sm.push("");
            }

            // Convert numeric/boolean values to fixed-width bytes via OP_NUM2BIN
            if prop.prop_type == "bigint" {
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(8))));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_NUM2BIN".to_string()));
                self.sm.pop(); // pop the width
            } else if prop.prop_type == "boolean" {
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(1))));
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
        let sb_consume =
            self.operand_consume(state_bytes_ref, &[preimage_ref, state_bytes_ref], binding_index, last_uses);
        self.bring_to_top(state_bytes_ref, sb_consume);

        // Extract amount from preimage for the continuation output.
        let pre_consume =
            self.operand_consume(preimage_ref, &[preimage_ref, state_bytes_ref], binding_index, last_uses);
        self.bring_to_top(preimage_ref, pre_consume);

        // Extract amount: last 52 bytes, take 8 bytes at offset 0.
        self.emit_op(StackOp::Opcode("OP_SIZE".into()));
        self.sm.push("");
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(52)))); // 8 (amount) + 44 (tail)
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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(8))));
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

        let cso_operands = [preimage_ref, state_bytes_ref, new_amount_ref];

        // Consume preimage ref (no longer needed — we use _codePart and _newAmount).
        let pre_consume = self.operand_consume(preimage_ref, &cso_operands, binding_index, last_uses);
        self.bring_to_top(preimage_ref, pre_consume);
        self.emit_op(StackOp::Drop);
        self.sm.pop();

        // Step 1: Convert _newAmount to 8-byte LE and save to altstack.
        let amount_consume = self.operand_consume(new_amount_ref, &cso_operands, binding_index, last_uses);
        self.bring_to_top(new_amount_ref, amount_consume);
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(8))));
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_NUM2BIN".into()));
        self.sm.pop();
        self.sm.pop();
        self.sm.push("");
        self.emit_op(StackOp::Opcode("OP_TOALTSTACK".into()));
        self.sm.pop();

        // Step 2: Bring stateBytes to stack.
        let sb_consume = self.operand_consume(state_bytes_ref, &cso_operands, binding_index, last_uses);
        self.bring_to_top(state_bytes_ref, sb_consume);

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
        let pkh_consume = self.operand_consume(pkh_ref, &[pkh_ref, amount_ref], binding_index, last_uses);
        self.bring_to_top(pkh_ref, pkh_consume);
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
        let amount_consume = self.operand_consume(amount_ref, &[pkh_ref, amount_ref], binding_index, last_uses);
        self.bring_to_top(amount_ref, amount_consume);
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(8))));
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
        let output_operands: Vec<&str> = std::iter::once(satoshis)
            .chain(state_values.iter().map(|s| s.as_str()))
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

            let consume = self.operand_consume(value_ref, &output_operands, binding_index, last_uses);
            self.bring_to_top(value_ref, consume);

            if prop.prop_type == "bigint" {
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(8))));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_NUM2BIN".to_string()));
                self.sm.pop();
            } else if prop.prop_type == "boolean" {
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(1))));
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
        let satoshis_consume = self.operand_consume(satoshis, &output_operands, binding_index, last_uses);
        self.bring_to_top(satoshis, satoshis_consume);
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(8))));
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
        let script_consume =
            self.operand_consume(script_bytes, &[satoshis, script_bytes], binding_index, last_uses);
        self.bring_to_top(script_bytes, script_consume);

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
        let sat_consume =
            self.operand_consume(satoshis, &[satoshis, script_bytes], binding_index, last_uses);
        self.bring_to_top(satoshis, sat_consume);
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(8))));
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
        _binding_index: usize,
        _last_uses: &HashMap<String, usize>,
    ) {
        // Metadata-only. Array literals in Rúnar today only feed into
        // checkMultiSig. Pre-laying the elements onto the runtime stack here
        // would desync the stack-map from the runtime stack (the map can only
        // model one slot per binding, but an array binding spans N runtime
        // slots). lower_check_multi_sig pulls each element to TOS at the use site.
        self.array_lengths
            .insert(binding_name.to_string(), elements.len());
        self.array_elements
            .insert(binding_name.to_string(), elements.to_vec());
    }

    /// Lower a `raw_script` ANF node to a single opaque `raw_bytes` StackOp.
    ///
    /// The bytes pass through verbatim — the emit pass writes them as-is, and
    /// the peephole optimizer must not bridge across them. Stack-tracker
    /// bookkeeping consumes `in_arity` items and pushes `out_arity` items named
    /// after the binding so downstream PICK/ROLL/DROP refer to the correct
    /// logical slot.
    fn lower_raw_script(
        &mut self,
        binding_name: &str,
        bytes_hex: &str,
        in_arity: usize,
        out_arity: usize,
    ) {
        if self.sm.depth() < in_arity {
            panic!(
                "raw_script binding '{}' requires {} stack items but only {} are present",
                binding_name,
                in_arity,
                self.sm.depth()
            );
        }
        let bytes = hex::decode(bytes_hex).unwrap_or_else(|e| {
            panic!(
                "raw_script binding '{}' has invalid hex bytes: {}",
                binding_name, e
            )
        });
        self.emit_op(StackOp::RawBytes {
            bytes,
            in_arity,
            out_arity,
        });
        for _ in 0..in_arity {
            self.sm.pop();
        }
        for i in 0..out_arity {
            let slot_name = if out_arity != 1 {
                format!("{}.{}", binding_name, i)
            } else {
                binding_name.to_string()
            };
            self.sm.push(&slot_name);
        }
        self.track_depth();
    }

    fn lower_check_multi_sig(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // Lower checkMultiSig([sig1..sigN], [pk1..pkM]).
        //
        // OP_CHECKMULTISIG expects the stack (bottom -> top):
        //   <dummy=OP_0> <sig1> ... <sigN> <N> <pk1> ... <pkM> <M>
        //
        // args[0] and args[1] are bindings produced by array_literal. Those
        // bindings are NOT physical stack slots — their element refs live on
        // the stack-map as individual named bindings. We pull each element to
        // TOS via bring_to_top. compute_last_uses propagates each element's
        // last-use through the array indirection to THIS binding.
        let sigs_ref = &args[0];
        let pks_ref = &args[1];
        let sig_elems = self
            .array_elements
            .get(sigs_ref)
            .cloned()
            .unwrap_or_else(|| panic!("checkMultiSig: array_literal metadata missing for sigs={}", sigs_ref));
        let pk_elems = self
            .array_elements
            .get(pks_ref)
            .cloned()
            .unwrap_or_else(|| panic!("checkMultiSig: array_literal metadata missing for pks={}", pks_ref));

        // Dummy OP_0 (historical CHECKMULTISIG off-by-one).
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(0))));
        self.sm.push("");

        // A ref repeated across the combined element list (e.g. the same
        // pubkey twice) must be copied at every position — see operand_consume.
        let msig_operands: Vec<&str> = sig_elems
            .iter()
            .map(|s| s.as_str())
            .chain(pk_elems.iter().map(|s| s.as_str()))
            .collect();

        // Bring each sig element to TOS in declaration order.
        for sig in &sig_elems {
            let consume = self.operand_consume(sig, &msig_operands, binding_index, last_uses);
            self.bring_to_top(sig, consume);
        }

        // Push nSigs.
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(sig_elems.len()))));
        self.sm.push("");

        // Bring each pubkey element to TOS in declaration order.
        for pk in &pk_elems {
            let consume = self.operand_consume(pk, &msig_operands, binding_index, last_uses);
            self.bring_to_top(pk, consume);
        }

        // Push nPKs.
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(pk_elems.len()))));
        self.sm.push("");

        // OP_CHECKMULTISIG consumes: dummy + N sigs + nSigs + M pks + nPKs.
        let consumed = 1 + sig_elems.len() + 1 + pk_elems.len() + 1;
        for _ in 0..consumed {
            self.sm.pop();
        }

        self.emit_op(StackOp::Opcode("OP_CHECKMULTISIG".to_string()));
        self.sm.push(binding_name);
        self.track_depth();
    }

    fn lower_check_preimage(
        &mut self,
        binding_name: &str,
        preimage: &str,
        sighash_flag: Option<i64>,
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // OP_PUSH_TX: verify the pushed BIP-143 sighash preimage is bound to the
        // current spending transaction. The signature is DERIVED FROM THE PREIMAGE
        // ON CHAIN (Optimal OP_PUSH_TX): s = (hash256(preimage) + r)*k⁻¹ mod n, with
        // fixed nonce k and privkey d=1 (pubkey = G). OP_CHECKSIG(sig, G) then passes
        // iff hash256(preimage) equals the node's real tx sighash — closing BUG-100.
        // The unlocking script pushes ONLY <preimage> (no witness signature).
        // See emit_check_preimage_binding (oppushtx.rs) for the construction.

        // Emit OP_CODESEPARATOR so the scriptCode in the BIP-143 preimage is only
        // the code after this point (smaller preimage; required for large scripts).
        self.emit_op(StackOp::Opcode("OP_CODESEPARATOR".to_string()));

        // Bring the preimage to the top (kept for field extractors below).
        let is_last = self.is_last_use(preimage, binding_index, last_uses);
        self.bring_to_top(preimage, is_last);

        // Derive + verify the signature on-chain (single opaque raw_bytes blob).
        // For the default ALL|FORKID (sighash_flag None) the blob is
        // byte-identical to the pinned cross-tier constant; issue #123 lets a
        // method declare a different mode, which only changes the appended
        // sighash flag byte. Net stack effect is zero.
        self.emit_check_preimage_binding(sighash_flag);

        // The preimage is now on top. Rename to binding name so field extractors
        // can reference it.
        self.sm.pop();
        self.sm.push(binding_name);

        self.track_depth();
    }

    /// Emit the on-chain preimage binding as one opaque `raw_bytes` op. Net stack
    /// effect is 0 (preimage in → preimage out), declared as in=1/out=1 so the
    /// static analyzer keeps the depth consistent. The stack tracker is updated
    /// by the caller (`lower_check_preimage`), mirroring the Go reference.
    fn emit_check_preimage_binding(&mut self, sighash_flag: Option<i64>) {
        self.emit_op(StackOp::RawBytes {
            bytes: super::oppushtx::check_preimage_binding_bytes_with_flag(sighash_flag),
            in_arity: 1,
            out_arity: 1,
        });
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
                // RabinSig / RabinPubKey are bigint aliases — same 8-byte layout.
                "RabinSig" | "RabinPubKey" => 8,
                "boolean" => 1,
                "PubKey" => 33,
                "Addr" => 20,
                // Ripemd160 is 20 bytes (same underlying type as Addr).
                "Ripemd160" => 20,
                "Sha256" => 32,
                "Point" => 64,
                // P-256 point: x[32] || y[32] = 64 bytes (same shape as Point).
                "P256Point" => 64,
                // P-384 point: x[48] || y[48] = 96 bytes.
                "P384Point" => 96,
                // ByteString-typed variable-length fields — treated the same as
                // ByteString (push-data-prefixed in state).
                "ByteString" | "Sig" | "SigHashPreimage" => { has_variable_length = true; -1 },
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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(104))));
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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(44))));
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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(8))));
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
            self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(state_len))));
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
            // Strip varint prefix from varint+scriptCode.
            //
            // BIP-143 scriptCode is prefixed by a Bitcoin varint:
            //   length < 0xfd:        1 byte (length itself)
            //   length <= 0xffff:     0xfd + 2 bytes LE                (3 bytes)
            //   length <= 0xffffffff: 0xfe + 4 bytes LE                (5 bytes)
            //   otherwise:            0xff + 8 bytes LE                (9 bytes)
            //
            // We must support all four shapes, otherwise scripts whose scriptCode
            // exceeds 65,535 bytes (e.g. embedded BN254 verifiers) silently
            // strip too few varint bytes and corrupt the subsequent
            // state-extraction OP_SPLITs (this is the bug fixed here — see
            // `integration/go/contracts/RollupBug.runar.go`).
            self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(1))));
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
            self.sm.pop(); self.sm.pop();
            self.sm.push(""); // firstByte
            self.sm.push(""); // rest
            self.emit_op(StackOp::Swap);
            self.sm.swap();
            // Zero-pad firstByte before BIN2NUM so 0xfd/0xfe/0xff aren't read
            // as negative script numbers.
            self.emit_op(StackOp::Push(PushValue::Bytes(vec![0])));
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_CAT".into()));
            self.sm.pop(); self.sm.pop();
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
            // Stack: [..., rest, fb_num]

            // emit_drop_more_varint_bytes drops `n` additional varint bytes
            // from the top-of-stack `rest`. Stack in: [..., rest], stack out:
            // [..., rest_minus_n].
            fn emit_drop_more_varint_bytes(ctx: &mut LoweringContext, n: i128) {
                ctx.emit_op(StackOp::Push(PushValue::Int(BigInt::from(n))));
                ctx.sm.push("");
                ctx.emit_op(StackOp::Opcode("OP_SPLIT".into()));
                ctx.sm.pop();
                ctx.sm.pop();
                ctx.sm.push("");
                ctx.sm.push("");
                ctx.emit_op(StackOp::Nip);
                ctx.sm.pop();
                ctx.sm.pop();
                ctx.sm.push("");
            }

            // IF fb_num < 253: 1-byte varint, drop fb_num.
            self.emit_op(StackOp::Dup);
            let top0 = self.sm.peek_at_depth(0).to_string();
            self.sm.push(&top0);
            self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(253))));
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_LESSTHAN".into()));
            self.sm.pop(); self.sm.pop();
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_IF".into()));
            self.sm.pop();
            let sm_at_1_byte_if = self.sm.clone();
            // THEN: 1-byte varint
            self.emit_op(StackOp::Drop);
            self.sm.pop();
            self.emit_op(StackOp::Opcode("OP_ELSE".into()));
            self.sm = sm_at_1_byte_if.clone();
            // ELSE: fb_num >= 253. Check 0xfe (5-byte varint) next.
            self.emit_op(StackOp::Dup);
            let top1 = self.sm.peek_at_depth(0).to_string();
            self.sm.push(&top1);
            self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(254))));
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_NUMEQUAL".into()));
            self.sm.pop(); self.sm.pop();
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_IF".into()));
            self.sm.pop();
            let sm_at_fe_if = self.sm.clone();
            // THEN: 5-byte varint (0xfe + 4 bytes LE).
            self.emit_op(StackOp::Drop);
            self.sm.pop();
            emit_drop_more_varint_bytes(self, 4);
            self.emit_op(StackOp::Opcode("OP_ELSE".into()));
            self.sm = sm_at_fe_if.clone();
            // ELSE: fb_num != 254. Check 0xff (9-byte varint) next.
            self.emit_op(StackOp::Dup);
            let top2 = self.sm.peek_at_depth(0).to_string();
            self.sm.push(&top2);
            self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(255))));
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_NUMEQUAL".into()));
            self.sm.pop(); self.sm.pop();
            self.sm.push("");
            self.emit_op(StackOp::Opcode("OP_IF".into()));
            self.sm.pop();
            let sm_at_ff_if = self.sm.clone();
            // THEN: 9-byte varint (0xff + 8 bytes LE).
            self.emit_op(StackOp::Drop);
            self.sm.pop();
            emit_drop_more_varint_bytes(self, 8);
            self.emit_op(StackOp::Opcode("OP_ELSE".into()));
            self.sm = sm_at_ff_if.clone();
            // ELSE: fb_num must be 253 (0xfd) — 3-byte varint.
            self.emit_op(StackOp::Drop);
            self.sm.pop();
            emit_drop_more_varint_bytes(self, 2);
            self.emit_op(StackOp::Opcode("OP_ENDIF".into()));
            self.emit_op(StackOp::Opcode("OP_ENDIF".into()));
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
            if is_numeric_state_type(&prop_types[0]) {
                self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
            }
            self.sm.pop();
            self.sm.push(&prop_names[0]);
        } else {
            for i in 0..num_props {
                let sz = prop_sizes[i];
                if i < num_props - 1 {
                    self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(sz))));
                    self.sm.push("");
                    self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                    self.sm.pop(); self.sm.pop();
                    self.sm.push(""); self.sm.push("");
                    self.emit_op(StackOp::Swap);
                    self.sm.swap();
                    if is_numeric_state_type(&prop_types[i]) {
                        self.emit_op(StackOp::Opcode("OP_BIN2NUM".to_string()));
                    }
                    self.emit_op(StackOp::Swap);
                    self.sm.swap();
                    self.sm.pop(); self.sm.pop();
                    self.sm.push(&prop_names[i]);
                    self.sm.push("");
                } else {
                    if is_numeric_state_type(&prop_types[i]) {
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
            if is_variable_length_state_type(&prop_types[0]) {
                // Variable-length byte-string: decode push-data prefix, drop trailing empty
                self.emit_push_data_decode(); // [..., data, remaining]
                self.emit_op(StackOp::Drop); self.sm.pop();
            } else if is_numeric_state_type(&prop_types[0]) {
                self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
            }
            self.sm.pop();
            self.sm.push(&prop_names[0]);
        } else {
            for i in 0..num_props {
                if i < num_props - 1 {
                    if is_variable_length_state_type(&prop_types[i]) {
                        // Variable-length byte-string: decode push-data prefix, extract data
                        self.emit_push_data_decode(); // [..., data, rest]
                        self.sm.pop(); self.sm.pop();
                        self.sm.push(&prop_names[i]);
                        self.sm.push(""); // rest on top
                    } else {
                        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(prop_sizes[i]))));
                        self.sm.push("");
                        self.emit_op(StackOp::Opcode("OP_SPLIT".into()));
                        self.sm.pop(); self.sm.pop();
                        self.sm.push(""); self.sm.push("");
                        self.emit_op(StackOp::Swap); self.sm.swap();
                        if is_numeric_state_type(&prop_types[i]) {
                            self.emit_op(StackOp::Opcode("OP_BIN2NUM".into()));
                        }
                        self.emit_op(StackOp::Swap); self.sm.swap();
                        self.sm.pop(); self.sm.pop();
                        self.sm.push(&prop_names[i]);
                        self.sm.push("");
                    }
                } else {
                    if is_variable_length_state_type(&prop_types[i]) {
                        // Last variable-length field: decode push-data prefix, drop trailing empty
                        self.emit_push_data_decode(); // [..., data, remaining]
                        self.emit_op(StackOp::Drop); self.sm.pop();
                    } else if is_numeric_state_type(&prop_types[i]) {
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(4))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(4))));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(32))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(36))));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(32))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(68))));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(36))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(4))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(8))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(4))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(40))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(32))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(52))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(8))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(44))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(4))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(104))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(52))));
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
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(100))));
                self.sm.push("");
                self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
                self.sm.pop();
                self.sm.push("");
                self.sm.push("");
                self.emit_op(StackOp::Nip);
                self.sm.pop();
                self.sm.pop();
                self.sm.push("");
                self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(4))));
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
        let obj_consume = self.operand_consume(obj, args, binding_index, last_uses);
        self.bring_to_top(obj, obj_consume);

        // Push the index onto the stack
        let index_consume = self.operand_consume(index, args, binding_index, last_uses);
        self.bring_to_top(index, index_consume);

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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(1))));
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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(0))));
        self.emit_op(StackOp::Swap);

        // 520 iterations (max BSV element size)
        for _ in 0..520 {
            // Stack: [result, data]
            self.emit_op(StackOp::Opcode("OP_DUP".to_string()));
            self.emit_op(StackOp::Opcode("OP_SIZE".to_string()));
            self.emit_op(StackOp::Nip);
            self.emit_op(StackOp::If {
                then_ops: vec![
                    StackOp::Push(PushValue::Int(BigInt::from(1))),
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

        let data_consume = self.operand_consume(data, args, binding_index, last_uses);
        self.bring_to_top(data, data_consume);

        let start_consume = self.operand_consume(start, args, binding_index, last_uses);
        self.bring_to_top(start, start_consume);

        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_SPLIT".to_string()));
        self.sm.push("");
        self.sm.push("");

        self.emit_op(StackOp::Nip);
        self.sm.pop();
        let right_part = self.sm.pop();
        self.sm.push(&right_part);

        let len_consume = self.operand_consume(length, args, binding_index, last_uses);
        self.bring_to_top(length, len_consume);

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
    /// Lower verifyRabinSig(msg, sig, padding, pubKey).
    /// The 10-opcode emission delegates to `super::rabin`.
    ///
    /// Stack input (bottom->top): msg sig padding pubKey
    /// Stack output:              bool
    fn lower_verify_rabin_sig(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 4, "verifyRabinSig requires 4 arguments");

        // Bring all 4 args to the top in argument order: msg sig padding pubKey
        for arg in args {
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
        }

        // Pop all 4 args from stack map
        self.sm.pop();
        self.sm.pop();
        self.sm.pop();
        self.sm.pop();

        super::rabin::emit_verify_rabin_sig(&mut |op| self.ops.push(op));

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

        let data_consume = self.operand_consume(data, args, binding_index, last_uses);
        self.bring_to_top(data, data_consume);

        let length_consume = self.operand_consume(length, args, binding_index, last_uses);
        self.bring_to_top(length, length_consume);

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

    /// WOTS+ signature verification with RFC 8391 tweakable hash (post-quantum).
    /// Brings all 3 args to the top, pops them, delegates to wots::emit_verify_wots,
    /// and pushes the boolean result.
    fn lower_verify_wots(
        &mut self,
        binding_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(args.len() >= 3, "verifyWOTS requires 3 arguments: msg, sig, pubkey");

        for arg in args.iter() {
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
        }
        for _ in 0..3 { self.sm.pop(); }

        // Delegate to wots module
        super::wots::emit_verify_wots(&mut |op| self.ops.push(op));

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
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
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
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
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
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
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
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
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
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
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
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
        }
        for _ in args {
            self.sm.pop();
        }

        // Snapshot before `emit` takes a mutable borrow of `self`.
        let ec_opts = self.ec_codegen;
        let emit = &mut |op: StackOp| self.ops.push(op);

        match func_name {
            "ecAdd" => super::ec::emit_ec_add(emit, ec_opts.as_ref()),
            "ecMul" => super::ec::emit_ec_mul(emit, ec_opts.as_ref()),
            "ecMulGen" => super::ec::emit_ec_mul_gen(emit, ec_opts.as_ref()),
            "ecNegate" => super::ec::emit_ec_negate(emit, ec_opts.as_ref()),
            "ecOnCurve" => super::ec::emit_ec_on_curve(emit, ec_opts.as_ref()),
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

    // -----------------------------------------------------------------------
    // NIST EC operations (P-256 / P-384) -- delegates to p256_p384.rs
    // -----------------------------------------------------------------------

    fn lower_nist_ec_builtin(
        &mut self,
        binding_name: &str,
        func_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // Bring args to top in order
        for arg in args.iter() {
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
        }
        for _ in args {
            self.sm.pop();
        }

        // Snapshot before `emit` takes a mutable borrow of `self`.
        let ec_opts = self.ec_codegen;
        let emit = &mut |op: StackOp| self.ops.push(op);

        match func_name {
            "p256Add" => super::p256_p384::emit_p256_add(emit, ec_opts.as_ref()),
            "p256Mul" => super::p256_p384::emit_p256_mul(emit, ec_opts.as_ref()),
            "p256MulGen" => super::p256_p384::emit_p256_mul_gen(emit, ec_opts.as_ref()),
            "p256Negate" => super::p256_p384::emit_p256_negate(emit, ec_opts.as_ref()),
            "p256OnCurve" => super::p256_p384::emit_p256_on_curve(emit, ec_opts.as_ref()),
            "p256EncodeCompressed" => super::p256_p384::emit_p256_encode_compressed(emit),
            "p384Add" => super::p256_p384::emit_p384_add(emit, ec_opts.as_ref()),
            "p384Mul" => super::p256_p384::emit_p384_mul(emit, ec_opts.as_ref()),
            "p384MulGen" => super::p256_p384::emit_p384_mul_gen(emit, ec_opts.as_ref()),
            "p384Negate" => super::p256_p384::emit_p384_negate(emit, ec_opts.as_ref()),
            "p384OnCurve" => super::p256_p384::emit_p384_on_curve(emit, ec_opts.as_ref()),
            "p384EncodeCompressed" => super::p256_p384::emit_p384_encode_compressed(emit),
            _ => panic!("unknown NIST EC builtin: {}", func_name),
        }

        self.sm.push(binding_name);
        self.track_depth();
    }

    // -----------------------------------------------------------------------
    // ECDSA verification (P-256 / P-384) -- delegates to p256_p384.rs
    // -----------------------------------------------------------------------

    fn lower_verify_ecdsa(
        &mut self,
        binding_name: &str,
        func_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        assert!(
            args.len() == 3,
            "{} requires exactly 3 arguments (msg, sig, pubkey)",
            func_name
        );
        // Bring all 3 args to top in order: msg, sig, pubkey
        for arg in args.iter() {
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
        }
        self.sm.pop(); // pubkey
        self.sm.pop(); // sig
        self.sm.pop(); // msg

        // Snapshot before `emit` takes a mutable borrow of `self`.
        let ec_opts = self.ec_codegen;
        let emit = &mut |op: StackOp| self.ops.push(op);

        if func_name == "verifyECDSA_P256" {
            super::p256_p384::emit_verify_ecdsa_p256(emit, ec_opts.as_ref());
        } else {
            super::p256_p384::emit_verify_ecdsa_p384(emit, ec_opts.as_ref());
        }

        self.sm.push(binding_name);
        self.track_depth();
    }

    // -----------------------------------------------------------------------
    // Baby Bear field arithmetic -- delegates to babybear.rs
    // -----------------------------------------------------------------------

    fn lower_bb_field_builtin(
        &mut self,
        binding_name: &str,
        func_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // Bring all args to stack top
        for arg in args.iter() {
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
        }
        for _ in args {
            self.sm.pop();
        }

        let emit = &mut |op: StackOp| self.ops.push(op);

        match func_name {
            "bbFieldAdd" => super::babybear::emit_bb_field_add(emit),
            "bbFieldSub" => super::babybear::emit_bb_field_sub(emit),
            "bbFieldMul" => super::babybear::emit_bb_field_mul(emit),
            "bbFieldInv" => super::babybear::emit_bb_field_inv(emit),
            "bbExt4Mul0" => super::babybear::emit_bb_ext4_mul_0(emit),
            "bbExt4Mul1" => super::babybear::emit_bb_ext4_mul_1(emit),
            "bbExt4Mul2" => super::babybear::emit_bb_ext4_mul_2(emit),
            "bbExt4Mul3" => super::babybear::emit_bb_ext4_mul_3(emit),
            "bbExt4Inv0" => super::babybear::emit_bb_ext4_inv_0(emit),
            "bbExt4Inv1" => super::babybear::emit_bb_ext4_inv_1(emit),
            "bbExt4Inv2" => super::babybear::emit_bb_ext4_inv_2(emit),
            "bbExt4Inv3" => super::babybear::emit_bb_ext4_inv_3(emit),
            _ => panic!("unknown Baby Bear builtin: {}", func_name),
        }

        self.sm.push(binding_name);
        self.track_depth();
    }

    // -----------------------------------------------------------------------
    // KoalaBear field arithmetic -- delegates to koalabear.rs
    // -----------------------------------------------------------------------

    fn lower_kb_field_builtin(
        &mut self,
        binding_name: &str,
        func_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // Bring all args to stack top
        for arg in args.iter() {
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
        }
        for _ in args {
            self.sm.pop();
        }

        let emit = &mut |op: StackOp| self.ops.push(op);

        match func_name {
            "kbFieldAdd" => super::koalabear::emit_kb_field_add(emit),
            "kbFieldSub" => super::koalabear::emit_kb_field_sub(emit),
            "kbFieldMul" => super::koalabear::emit_kb_field_mul(emit),
            "kbFieldInv" => super::koalabear::emit_kb_field_inv(emit),
            "kbExt4Mul0" => super::koalabear::emit_kb_ext4_mul_0(emit),
            "kbExt4Mul1" => super::koalabear::emit_kb_ext4_mul_1(emit),
            "kbExt4Mul2" => super::koalabear::emit_kb_ext4_mul_2(emit),
            "kbExt4Mul3" => super::koalabear::emit_kb_ext4_mul_3(emit),
            "kbExt4Inv0" => super::koalabear::emit_kb_ext4_inv_0(emit),
            "kbExt4Inv1" => super::koalabear::emit_kb_ext4_inv_1(emit),
            "kbExt4Inv2" => super::koalabear::emit_kb_ext4_inv_2(emit),
            "kbExt4Inv3" => super::koalabear::emit_kb_ext4_inv_3(emit),
            _ => panic!("unknown KoalaBear builtin: {}", func_name),
        }

        self.sm.push(binding_name);
        self.track_depth();
    }

    // -----------------------------------------------------------------------
    // BN254 field + G1 operations -- delegates to bn254.rs
    // -----------------------------------------------------------------------

    fn lower_bn254_builtin(
        &mut self,
        binding_name: &str,
        func_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // Bring all args to stack top in order
        for arg in args.iter() {
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
        }
        for _ in args {
            self.sm.pop();
        }

        let emit = &mut |op: StackOp| self.ops.push(op);

        match func_name {
            "bn254FieldAdd" => super::bn254::emit_bn254_field_add(emit),
            "bn254FieldSub" => super::bn254::emit_bn254_field_sub(emit),
            "bn254FieldMul" => super::bn254::emit_bn254_field_mul(emit),
            "bn254FieldInv" => super::bn254::emit_bn254_field_inv(emit),
            "bn254FieldNeg" => super::bn254::emit_bn254_field_neg(emit),
            "bn254G1Add" => super::bn254::emit_bn254_g1_add(emit),
            "bn254G1ScalarMul" => super::bn254::emit_bn254_g1_scalar_mul(emit),
            "bn254G1Negate" => super::bn254::emit_bn254_g1_negate(emit),
            "bn254G1OnCurve" => super::bn254::emit_bn254_g1_on_curve(emit),
            _ => panic!("unknown BN254 builtin: {}", func_name),
        }

        self.sm.push(binding_name);
        self.track_depth();
    }

    // -----------------------------------------------------------------------
    // Merkle proof verification -- delegates to merkle.rs
    // -----------------------------------------------------------------------

    fn lower_merkle_root(
        &mut self,
        binding_name: &str,
        func_name: &str,
        args: &[String],
        binding_index: usize,
        last_uses: &HashMap<String, usize>,
    ) {
        // args: [leaf, proof, index, depth]
        // depth must be a compile-time constant
        assert!(
            args.len() == 4,
            "{} requires exactly 4 arguments (leaf, proof, index, depth)",
            func_name
        );

        // Extract depth constant from ANF binding
        let depth_arg = &args[3];
        let depth_value = self.const_values.get(depth_arg).cloned();
        let depth = match depth_value {
            Some(ConstValue::Int(n)) => {
                use num_traits::ToPrimitive;
                n.to_usize().unwrap_or_else(|| panic!(
                    "{}: depth (4th argument) must fit in usize, got {}", func_name, n
                ))
            }
            _ => panic!(
                "{}: depth (4th argument) must be a compile-time constant integer literal. \
                 Got a runtime value for '{}'.",
                func_name, depth_arg
            ),
        };
        assert!(
            depth >= 1 && depth <= 64,
            "{}: depth must be between 1 and 64, got {}",
            func_name, depth
        );

        // Remove depth from the real stack FIRST (compile-time constant, not runtime).
        if self.sm.has(depth_arg) {
            self.bring_to_top(depth_arg, true);
            self.emit_op(StackOp::Drop);
            self.sm.pop();
        }

        // Bring leaf, proof, index to stack top for the codegen
        for i in 0..3 {
            let arg = &args[i];
            let consume = self.operand_consume(arg, args, binding_index, last_uses);
            self.bring_to_top(arg, consume);
        }
        // Pop the 3 args -- the codegen consumes them and produces 1 result
        for _ in 0..3 {
            self.sm.pop();
        }

        let emit = &mut |op: StackOp| self.ops.push(op);

        match func_name {
            "merkleRootSha256" => super::merkle::emit_merkle_root_sha256(emit, depth),
            "merkleRootHash256" => super::merkle::emit_merkle_root_hash256(emit, depth),
            "merkleRootPoseidon2KB" => super::poseidon2_merkle::emit_poseidon2_merkle_root(emit, depth),
            _ => panic!("unknown Merkle builtin: {}", func_name),
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

        let a_consume = self.operand_consume(&args[0], args, binding_index, last_uses);
        self.bring_to_top(&args[0], a_consume);

        let b_consume = self.operand_consume(&args[1], args, binding_index, last_uses);
        self.bring_to_top(&args[1], b_consume);

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

        let a_consume = self.operand_consume(&args[0], args, binding_index, last_uses);
        self.bring_to_top(&args[0], a_consume);

        let b_consume = self.operand_consume(&args[1], args, binding_index, last_uses);
        self.bring_to_top(&args[1], b_consume);

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

        let val_consume = self.operand_consume(&args[0], args, binding_index, last_uses);
        self.bring_to_top(&args[0], val_consume);

        let lo_consume = self.operand_consume(&args[1], args, binding_index, last_uses);
        self.bring_to_top(&args[1], lo_consume);

        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_MAX".to_string()));
        self.sm.push(""); // intermediate result

        let hi_consume = self.operand_consume(&args[2], args, binding_index, last_uses);
        self.bring_to_top(&args[2], hi_consume);

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

        let base_consume = self.operand_consume(&args[0], args, binding_index, last_uses);
        self.bring_to_top(&args[0], base_consume);

        let exp_consume = self.operand_consume(&args[1], args, binding_index, last_uses);
        self.bring_to_top(&args[1], exp_consume);

        self.sm.pop();
        self.sm.pop();

        // Stack: base exp
        self.emit_op(StackOp::Swap);                                  // exp base
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(1))));               // exp base 1(acc)

        for i in 0..32 {
            // Stack: exp base acc
            self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(2))));
            self.emit_op(StackOp::Opcode("OP_PICK".to_string()));     // exp base acc exp
            self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(i))));
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

        let a_consume = self.operand_consume(&args[0], args, binding_index, last_uses);
        self.bring_to_top(&args[0], a_consume);

        let b_consume = self.operand_consume(&args[1], args, binding_index, last_uses);
        self.bring_to_top(&args[1], b_consume);

        self.sm.pop();
        self.sm.pop();
        self.emit_op(StackOp::Opcode("OP_MUL".to_string()));
        self.sm.push(""); // a*b

        let c_consume = self.operand_consume(&args[2], args, binding_index, last_uses);
        self.bring_to_top(&args[2], c_consume);

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

        let amount_consume = self.operand_consume(&args[0], args, binding_index, last_uses);
        self.bring_to_top(&args[0], amount_consume);

        let bps_consume = self.operand_consume(&args[1], args, binding_index, last_uses);
        self.bring_to_top(&args[1], bps_consume);

        self.sm.pop();
        self.sm.pop();

        self.emit_op(StackOp::Opcode("OP_MUL".to_string()));
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(10000))));
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
            newton_ops.push(StackOp::Push(PushValue::Int(BigInt::from(2))));            // n (guess + n/guess) 2
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

        let a_consume = self.operand_consume(&args[0], args, binding_index, last_uses);
        self.bring_to_top(&args[0], a_consume);

        let b_consume = self.operand_consume(&args[1], args, binding_index, last_uses);
        self.bring_to_top(&args[1], b_consume);

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

        let a_consume = self.operand_consume(&args[0], args, binding_index, last_uses);
        self.bring_to_top(&args[0], a_consume);

        let b_consume = self.operand_consume(&args[1], args, binding_index, last_uses);
        self.bring_to_top(&args[1], b_consume);

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
        self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(0)))); // n 0

        // 64 iterations (sufficient for Bitcoin Script bigint range)
        const LOG2_ITERATIONS: usize = 64;
        for _ in 0..LOG2_ITERATIONS {
            // Stack: input counter
            self.emit_op(StackOp::Swap);                                     // counter input
            self.emit_op(StackOp::Opcode("OP_DUP".to_string()));            // counter input input
            self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(1))));                  // counter input input 1
            self.emit_op(StackOp::Opcode("OP_GREATERTHAN".to_string()));     // counter input (input>1)
            self.emit_op(StackOp::If {
                then_ops: vec![
                    StackOp::Push(PushValue::Int(BigInt::from(2))),                        // counter input 2
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
    lower_to_stack_with_ec(program, None)
}

/// `lower_to_stack` with the EXPERIMENTAL EC script-size options.
///
/// `None` keeps every EC emitter byte-identical to the shipping output; see
/// `EcCodegenOptions` and docs/experiments/script-size-optimizer-results.md.
pub fn lower_to_stack_with_ec(
    program: &ANFProgram,
    ec_codegen: Option<super::ec::EcCodegenOptions>,
) -> Result<Vec<StackMethod>, String> {
    // Convert any panic (stack underflow, unknown operator, type mismatch, or a
    // deliberate refusal) into an error return instead of crashing the process
    // — and without the default panic hook printing a crash report first. See
    // `crate::refusal`.
    crate::refusal::catch_refusal("stack lowering", || lower_to_stack_inner(program, ec_codegen))
        .and_then(|inner| inner)
}

fn lower_to_stack_inner(
    program: &ANFProgram,
    ec_codegen: Option<super::ec::EcCodegenOptions>,
) -> Result<Vec<StackMethod>, String> {
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
        let sm = lower_method_with_private_methods(
            method, &program.properties, &private_methods, ec_codegen)?;
        methods.push(sm);
    }

    Ok(methods)
}

/// Check whether a method's body contains a CheckPreimage binding,
/// recursing through if/loop branches and into private-method bodies.
/// If found, the unlocking script will push an implicit <sig>
/// parameter before all declared parameters (OP_PUSH_TX pattern).
/// Recursion is the 2026-04-30 audit finding F7 fix.
fn method_uses_check_preimage(
    bindings: &[ANFBinding],
    private_methods: Option<&HashMap<String, ANFMethod>>,
) -> bool {
    let mut seen: HashSet<String> = HashSet::new();
    method_uses_check_preimage_rec(bindings, private_methods, &mut seen)
}

fn method_uses_check_preimage_rec(
    bindings: &[ANFBinding],
    private_methods: Option<&HashMap<String, ANFMethod>>,
    seen: &mut HashSet<String>,
) -> bool {
    for b in bindings {
        match &b.value {
            ANFValue::CheckPreimage { .. } => return true,
            ANFValue::If { then, else_branch, .. } => {
                if method_uses_check_preimage_rec(then, private_methods, seen) {
                    return true;
                }
                if method_uses_check_preimage_rec(else_branch, private_methods, seen) {
                    return true;
                }
            }
            ANFValue::Loop { body, .. } => {
                if method_uses_check_preimage_rec(body, private_methods, seen) {
                    return true;
                }
            }
            ANFValue::MethodCall { method, .. } => {
                if let Some(privs) = private_methods {
                    if let Some(target) = privs.get(method) {
                        if !seen.contains(&target.name) {
                            seen.insert(target.name.clone());
                            if method_uses_check_preimage_rec(&target.body, private_methods, seen) {
                                return true;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    false
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

/// Whether a method READS a mutable variable-length (ByteString) state field's
/// value (via `load_prop`), recursing into branches and loops. Issue #100: such
/// a terminal method needs `_codePart` for the preimage-relative state offset.
/// A method that only reads readonly fields (baked into the locking script) or
/// fixed-size mutable fields does NOT need `_codePart` — narrowing to the live
/// var-length read avoids over-provisioning (e.g. MessageBoard.burn reads only
/// the readonly owner and must keep its original terminal codegen).
/// Also recurses into private-method bodies (deep-review finding C18): private
/// methods are inlined into the caller's stack context, so a read that only
/// happens inside a private helper still needs `_codePart` in the public entry.
fn method_reads_var_len_state(
    bindings: &[ANFBinding],
    var_len_props: &std::collections::HashSet<String>,
    private_methods: Option<&HashMap<String, ANFMethod>>,
) -> bool {
    let mut seen: HashSet<String> = HashSet::new();
    method_reads_var_len_state_rec(bindings, var_len_props, private_methods, &mut seen)
}

fn method_reads_var_len_state_rec(
    bindings: &[ANFBinding],
    var_len_props: &std::collections::HashSet<String>,
    private_methods: Option<&HashMap<String, ANFMethod>>,
    seen: &mut HashSet<String>,
) -> bool {
    for b in bindings {
        match &b.value {
            ANFValue::LoadProp { name } => {
                if var_len_props.contains(name) {
                    return true;
                }
            }
            ANFValue::If { then, else_branch, .. } => {
                if method_reads_var_len_state_rec(then, var_len_props, private_methods, seen) {
                    return true;
                }
                if method_reads_var_len_state_rec(else_branch, var_len_props, private_methods, seen)
                {
                    return true;
                }
            }
            ANFValue::Loop { body, .. } => {
                if method_reads_var_len_state_rec(body, var_len_props, private_methods, seen) {
                    return true;
                }
            }
            ANFValue::MethodCall { method, .. } => {
                if let Some(privs) = private_methods {
                    if let Some(target) = privs.get(method) {
                        if !seen.contains(&target.name) {
                            seen.insert(target.name.clone());
                            if method_reads_var_len_state_rec(
                                &target.body,
                                var_len_props,
                                private_methods,
                                seen,
                            ) {
                                return true;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn lower_method_with_private_methods(
    method: &ANFMethod,
    properties: &[ANFProperty],
    private_methods: &HashMap<String, ANFMethod>,
    ec_codegen: Option<super::ec::EcCodegenOptions>,
) -> Result<StackMethod, String> {
    let mut param_names: Vec<String> = method.params.iter().map(|p| p.name.clone()).collect();

    // If the method uses checkPreimage, the unlocking script pushes implicit
    // params before all declared parameters (OP_PUSH_TX pattern).
    // _codePart: full code script (locking script minus state) as ByteString.
    // (BUG-100 fix: the OP_PUSH_TX signature is now derived on-chain from the
    // preimage — see lower_check_preimage — so NO _opPushTxSig witness item is
    // pushed. The unlocking script provides only the preimage.)
    // _codePart is needed for continuation builders (add_output/add_raw_output)
    // OR when the method reads a mutable variable-length (ByteString) state
    // field — the deserialization needs it for the preimage-relative offset
    // (issue #100).
    let var_len_props: std::collections::HashSet<String> = properties
        .iter()
        .filter(|p| !p.readonly && p.prop_type == "ByteString")
        .map(|p| p.name.clone())
        .collect();
    let uses_code_part = method_uses_check_preimage(&method.body, Some(private_methods))
        && (method_uses_code_part(&method.body)
            || method_reads_var_len_state(&method.body, &var_len_props, Some(private_methods)));
    if uses_code_part {
        param_names.insert(0, "_codePart".to_string());
    }

    let mut ctx = LoweringContext::new(&param_names, properties);
    ctx.private_methods = private_methods.clone();
    ctx.ec_codegen = ec_codegen;
    // Pass terminal_assert=true for public methods so the last assert leaves
    // its value on the stack (Bitcoin Script requires a truthy top-of-stack).
    ctx.lower_bindings(&method.body, method.is_public);

    // Clean up excess stack items below the top-of-stack boolean (CLEANSTACK).
    // Excess items can come from deserialize_state (stateful methods reading
    // mutable fields) or from readonly-field-binding patterns in all-readonly
    // terminal methods. The depth>1 guard keeps this a no-op for already-clean
    // methods.
    if method.is_public && ctx.sm.depth() > 1 {
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
        source_locs: ctx.source_locs,
        ops: ctx.ops,
        max_stack_depth: ctx.max_depth,
        uses_code_part,
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
            parent_class: String::new(),
            properties: vec![ANFProperty {
                name: "pubKeyHash".to_string(),
                prop_type: "Addr".to_string(),
                readonly: true,
                initial_value: None,
                synthetic_array_chain: None,
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::LoadParam {
                            name: "pubKey".to_string(),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadProp {
                            name: "pubKeyHash".to_string(),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::Call {
                            func: "hash160".to_string(),
                            args: vec!["t1".to_string()],
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::BinOp {
                            op: "===".to_string(),
                            left: "t3".to_string(),
                            right: "t2".to_string(),
                            result_type: None,
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t5".to_string(),
                        value: ANFValue::Assert { value: "t4".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t6".to_string(),
                        value: ANFValue::Call {
                            func: "checkSig".to_string(),
                            args: vec!["t0".to_string(), "t1".to_string()],
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t7".to_string(),
                        value: ANFValue::Assert { value: "t6".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
            properties: vec![ANFProperty {
                name: "val".to_string(),
                prop_type: "bigint".to_string(),
                readonly: false,
                initial_value: Some(serde_json::Value::Number(serde_json::Number::from(0))),
                synthetic_array_chain: None,
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "extractOutputHash".to_string(),
                            args: vec!["t0".to_string()],
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst { value: serde_json::Value::Bool(true) },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::Assert { value: "t2".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::LoadParam { name: "x".to_string() },
                        source_loc: None,
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
                                    source_loc: None,
                                },
                                ANFBinding {
                                    name: "t4".to_string(),
                                    value: ANFValue::BinOp {
                                        op: ">".to_string(),
                                        left: "t1".to_string(),
                                        right: "t3".to_string(),
                                        result_type: None,
                                    },
                                    source_loc: None,
                                },
                                ANFBinding {
                                    name: "t5".to_string(),
                                    value: ANFValue::Assert { value: "t4".to_string(), is_auto_injected_state_check: false },
                                    source_loc: None,
                                },
                            ],
                            else_branch: vec![
                                ANFBinding {
                                    name: "t6".to_string(),
                                    value: ANFValue::LoadConst {
                                        value: serde_json::Value::Number(serde_json::Number::from(5)),
                                    },
                                    source_loc: None,
                                },
                                ANFBinding {
                                    name: "t7".to_string(),
                                    value: ANFValue::BinOp {
                                        op: ">".to_string(),
                                        left: "t1".to_string(),
                                        right: "t6".to_string(),
                                        result_type: None,
                                    },
                                    source_loc: None,
                                },
                                ANFBinding {
                                    name: "t8".to_string(),
                                    value: ANFValue::Assert { value: "t7".to_string(), is_auto_injected_state_check: false },
                                    source_loc: None,
                                },
                            ],
                            results: Vec::new(),
                        },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "unpack".to_string(),
                            args: vec!["t0".to_string()],
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Number(serde_json::Number::from(42)),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::BinOp {
                            op: "===".to_string(),
                            left: "t1".to_string(),
                            right: "t2".to_string(),
                            result_type: None,
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::Assert { value: "t3".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "pack".to_string(),
                            args: vec!["t0".to_string()],
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Bool(true),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::Assert { value: "t2".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "toByteString".to_string(),
                            args: vec!["t0".to_string()],
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Bool(true),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::Assert { value: "t2".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "sqrt".to_string(),
                            args: vec!["t0".to_string()],
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Number(serde_json::Number::from(0)),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::BinOp {
                            op: ">=".to_string(),
                            left: "t1".to_string(),
                            right: "t2".to_string(),
                            result_type: None,
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::Assert { value: "t3".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t_loop".to_string(),
                        value: ANFValue::Loop {
                            count: 3,
                            start: serde_json::json!(0),
                            step: 1,
                            body: vec![
                                // Body uses x but not iter var __i, and asserts consume
                                ANFBinding {
                                    name: "t1".to_string(),
                                    value: ANFValue::LoadParam { name: "x".to_string() },
                                    source_loc: None,
                                },
                                ANFBinding {
                                    name: "t2".to_string(),
                                    value: ANFValue::Assert { value: "t1".to_string(), is_auto_injected_state_check: false },
                                    source_loc: None,
                                },
                            ],
                            iter_var: "__i".to_string(),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t_final".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Bool(true),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t_assert".to_string(),
                        value: ANFValue::Assert { value: "t_final".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
        use num_traits::ToPrimitive;
        // Verify that PushValue::Int can hold values larger than i64::MAX
        let large_val: i128 = (i64::MAX as i128) + 1;
        let push = PushValue::Int(BigInt::from(large_val));
        if let PushValue::Int(v) = push {
            assert_eq!(v.to_i128(), Some(large_val), "PushValue::Int should store values > i64::MAX without truncation");
        } else {
            panic!("expected PushValue::Int");
        }

        // Also test negative extreme
        let neg_val: i128 = (i64::MIN as i128) - 1;
        let push_neg = PushValue::Int(BigInt::from(neg_val));
        if let PushValue::Int(v) = push_neg {
            assert_eq!(v.to_i128(), Some(neg_val), "PushValue::Int should store values < i64::MIN without truncation");
        } else {
            panic!("expected PushValue::Int");
        }
    }

    #[test]
    fn test_push_value_int_encodes_large_number() {
        // Verify that a large number (> i64::MAX) can be pushed and encoded
        use crate::codegen::emit::encode_push_int;

        let large_val: i128 = 1i128 << 100;
        let (hex, _asm) = encode_push_int(&BigInt::from(large_val));
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
            parent_class: String::new(),
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "log2".to_string(),
                            args: vec!["t0".to_string()],
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Number(serde_json::Number::from(0)),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::BinOp {
                            op: ">=".to_string(),
                            left: "t1".to_string(),
                            right: "t2".to_string(),
                            result_type: None,
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::Assert { value: "t3".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "reverseBytes".to_string(),
                            args: vec!["t0".to_string()],
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Bool(true),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::Assert { value: "t2".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
            properties: vec![],
            methods: vec![
                ANFMethod {
                    name: "constructor".to_string(),
                    params: vec![],
                    body: vec![],
                    is_public: false,
                    sighash_type: None,
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
                            source_loc: None,
                        },
                        ANFBinding {
                            name: "t1".to_string(),
                            value: ANFValue::LoadConst {
                                value: serde_json::Value::Number(serde_json::Number::from(42)),
                            },
                            source_loc: None,
                        },
                        ANFBinding {
                            name: "t2".to_string(),
                            value: ANFValue::BinOp {
                                op: "===".to_string(),
                                left: "t0".to_string(),
                                right: "t1".to_string(),
                                result_type: None,
                            },
                            source_loc: None,
                        },
                        ANFBinding {
                            name: "t3".to_string(),
                            value: ANFValue::Assert { value: "t2".to_string(), is_auto_injected_state_check: false },
                            source_loc: None,
                        },
                    ],
                    is_public: true,
                    sighash_type: None,
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
                            source_loc: None,
                        },
                        ANFBinding {
                            name: "t1".to_string(),
                            value: ANFValue::LoadConst {
                                value: serde_json::Value::Number(serde_json::Number::from(100)),
                            },
                            source_loc: None,
                        },
                        ANFBinding {
                            name: "t2".to_string(),
                            value: ANFValue::BinOp {
                                op: "===".to_string(),
                                left: "t0".to_string(),
                                right: "t1".to_string(),
                                result_type: None,
                            },
                            source_loc: None,
                        },
                        ANFBinding {
                            name: "t3".to_string(),
                            value: ANFValue::Assert { value: "t2".to_string(), is_auto_injected_state_check: false },
                            source_loc: None,
                        },
                    ],
                    is_public: true,
                    sighash_type: None,
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
            parent_class: String::new(),
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "extractOutputs".to_string(),
                            args: vec!["t0".to_string()],
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::Assert { value: "t1".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
            properties: vec![ANFProperty {
                name: "target".to_string(),
                prop_type: "bigint".to_string(),
                readonly: true,
                initial_value: None,
                synthetic_array_chain: None,
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::LoadParam { name: "b".to_string() },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::BinOp {
                            op: "+".to_string(),
                            left: "t0".to_string(),
                            right: "t1".to_string(),
                            result_type: None,
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::LoadProp { name: "target".to_string() },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::BinOp {
                            op: "===".to_string(),
                            left: "t2".to_string(),
                            right: "t3".to_string(),
                            result_type: None,
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t5".to_string(),
                        value: ANFValue::Assert { value: "t4".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::LoadParam { name: "b".to_string() },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::BinOp {
                            op: "+".to_string(),
                            left: "t0".to_string(),
                            right: "t1".to_string(),
                            result_type: Some("bytes".to_string()), // ByteString concat
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::LoadParam { name: "expected".to_string() },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::BinOp {
                            op: "===".to_string(),
                            left: "t2".to_string(),
                            right: "t3".to_string(),
                            result_type: Some("bytes".to_string()),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t5".to_string(),
                        value: ANFValue::Assert { value: "t4".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
            parent_class: String::new(),
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
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "log2".to_string(),
                            args: vec!["t0".to_string()],
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::Value::Number(serde_json::Number::from(0)),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::BinOp {
                            op: ">=".to_string(),
                            left: "t1".to_string(),
                            right: "t2".to_string(),
                            result_type: None,
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::Assert { value: "t3".to_string(), is_auto_injected_state_check: false },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
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
