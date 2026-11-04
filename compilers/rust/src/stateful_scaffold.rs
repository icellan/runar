//! N-101: `--ir` input skips the frontend, so a program labelled (or, per
//! N-087, inferred) StatefulSmartContract could omit or fake the scaffolding
//! ANF lowering injects into every public method and compile to an
//! anyone-can-spend script: F-107's attack body compiled to `76767b8777`. For
//! each public method this re-derives what the frontend would inject (the
//! TypeScript reference is packages/runar-compiler/src/passes/stateful-scaffold.ts):
//!
//! - prologue: `assert(checkPreimage(txPreimage))`, the sighash-type assert
//!   and, when the contract has mutable properties, `deserialize_state`;
//! - user code: free;
//! - continuation, when the method mutates state or declares outputs: the
//!   `_newAmount` floor (single-output form), the change output and the
//!   hashOutputs comparison over every output in order;
//!
//! and refuses the program, with the diagnostics all seven tiers share
//! (conformance/negatives/ir-stateful-scaffold-cases.json), when (1) the
//! auto-injected parameters, (2) the prologue or (3) the continuation differ,
//! or (4) a scaffolding binding, or an output the continuation commits to, is
//! bound more than once or shares a property or parameter name.

use std::collections::{HashMap, HashSet};

use crate::ir::{parse_const_value, ANFBinding, ANFMethod, ANFProgram, ANFValue, ConstValue};

const SIGHASH_DEFAULT: i64 = 0x41;

struct Emitter<'a> {
    taken: &'a HashSet<String>,
    next: &'a std::cell::Cell<usize>,
    out: Vec<ANFBinding>,
}

impl<'a> Emitter<'a> {
    fn new(taken: &'a HashSet<String>, next: &'a std::cell::Cell<usize>) -> Self {
        Emitter { taken, next, out: Vec::new() }
    }
    fn emit(&mut self, value: ANFValue) -> String {
        let name = loop {
            let n = format!("$scaffold{}", self.next.get());
            self.next.set(self.next.get() + 1);
            if !self.taken.contains(&n) {
                break n;
            }
        };
        self.out.push(ANFBinding { name: name.clone(), value, source_loc: None });
        name
    }
    fn sub(&self) -> Emitter<'a> {
        Emitter::new(self.taken, self.next)
    }
}

fn load_param(name: &str) -> ANFValue {
    ANFValue::LoadParam { name: name.to_string() }
}
fn call(func: &str, args: &[&str]) -> ANFValue {
    ANFValue::Call { func: func.to_string(), args: args.iter().map(|a| a.to_string()).collect() }
}
fn bin_op(op: &str, left: &str, right: &str, result_type: Option<&str>) -> ANFValue {
    ANFValue::BinOp {
        op: op.to_string(),
        left: left.to_string(),
        right: right.to_string(),
        result_type: result_type.map(|s| s.to_string()),
    }
}
fn assert(value: &str, auto: bool) -> ANFValue {
    ANFValue::Assert { value: value.to_string(), is_auto_injected_state_check: auto }
}

fn prologue(e: &mut Emitter, sighash_mode: i64, has_mutable_state: bool) {
    let pre = e.emit(load_param("txPreimage"));
    let flag = if sighash_mode == SIGHASH_DEFAULT { None } else { Some(sighash_mode) };
    let check = e.emit(ANFValue::CheckPreimage { preimage: pre, sighash_flag: flag, binding_variant: None });
    e.emit(assert(&check, false));
    let p2 = e.emit(load_param("txPreimage"));
    let typ = e.emit(call("extractSigHashType", &[&p2]));
    let want = e.emit(ANFValue::LoadConst { value: serde_json::Value::from(sighash_mode) });
    let ok = e.emit(bin_op("===", &typ, &want, None));
    e.emit(assert(&ok, false));
    if has_mutable_state {
        let p3 = e.emit(load_param("txPreimage"));
        e.emit(ANFValue::DeserializeState { preimage: p3 });
    }
}

fn continuation(
    e: &mut Emitter,
    needs_change: bool,
    includes_change: bool,
    state_refs: &[String],
    data_refs: &[String],
) {
    if !needs_change {
        return;
    }
    if state_refs.is_empty() {
        let p = e.emit(load_param("txPreimage"));
        let input = e.emit(call("extractAmount", &[&p]));
        let na = e.emit(load_param("_newAmount"));
        let ok = e.emit(bin_op(">=", &na, &input, None));
        e.emit(assert(&ok, false));
    }
    // N-038: no change segment under a SIGHASH_SINGLE base.
    let change = if includes_change {
        let pkh = e.emit(load_param("_changePKH"));
        let amt = e.emit(load_param("_changeAmount"));
        let zero = e.emit(ANFValue::LoadConst { value: serde_json::Value::from(0) });
        let non_zero = e.emit(bin_op("!==", &amt, &zero, None));
        let mut then_e = e.sub();
        then_e.emit(call("buildChangeOutput", &[&pkh, &amt]));
        let mut else_e = e.sub();
        else_e.emit(ANFValue::LoadConst { value: serde_json::Value::from("") });
        let (then, else_branch) = (then_e.out, else_e.out);
        Some(e.emit(ANFValue::If { cond: non_zero, then, else_branch, results: Vec::new() }))
    } else {
        None
    };

    let mut acc = if let Some((first, more)) = state_refs.split_first() {
        let mut acc = first.clone();
        for r in more {
            acc = e.emit(call("cat", &[&acc, r]));
        }
        acc
    } else {
        let script = e.emit(ANFValue::GetStateScript {});
        let p = e.emit(load_param("txPreimage"));
        let na = e.emit(load_param("_newAmount"));
        e.emit(call("computeStateOutput", &[&p, &script, &na]))
    };
    for r in data_refs {
        acc = e.emit(call("cat", &[&acc, r]));
    }
    if let Some(change) = change {
        acc = e.emit(call("cat", &[&acc, &change]));
    }
    let hash = e.emit(call("hash256", &[&acc]));
    let p = e.emit(load_param("txPreimage"));
    let out_hash = e.emit(call("extractOutputHash", &[&p]));
    let eq = e.emit(bin_op("===", &hash, &out_hash, Some("bytes")));
    e.emit(assert(&eq, true));
}

fn nested(v: &ANFValue) -> Vec<&Vec<ANFBinding>> {
    match v {
        ANFValue::If { then, else_branch, .. } => vec![then, else_branch],
        ANFValue::Loop { body, .. } => vec![body],
        _ => Vec::new(),
    }
}

fn is_state_output(v: &ANFValue) -> bool {
    matches!(v, ANFValue::AddOutput { .. } | ANFValue::AddRawOutput { .. })
}
fn is_data_output(v: &ANFValue) -> bool {
    matches!(v, ANFValue::AddDataOutput { .. })
}

fn contains(bindings: &[ANFBinding], pred: fn(&ANFValue) -> bool) -> bool {
    bindings.iter().any(|b| pred(&b.value) || nested(&b.value).into_iter().any(|n| contains(n, pred)))
}

/// The frontend's side-effect summary, read off the IR (update_prop is a state
/// mutation, add_output / add_raw_output a state output, add_data_output a
/// data output) at any depth and through method_calls to private methods.
/// (needs_change, includes_change, needs_new_amount) — `includes_change` reads
/// the method's own `sigHashType` (N-038).
pub(crate) fn shape(program: &ANFProgram, method: &ANFMethod) -> (bool, bool, bool) {
    let privates: HashMap<&str, &ANFMethod> = program
        .methods
        .iter()
        .filter(|m| !m.is_public && m.name != "constructor")
        .map(|m| (m.name.as_str(), m))
        .collect();
    let (mut mutates, mut state_out, mut data_out) = (false, false, false);
    let mut visited: HashSet<String> = HashSet::new();
    let mut stack: Vec<&Vec<ANFBinding>> = vec![&method.body];
    while let Some(bindings) = stack.pop() {
        for b in bindings {
            match &b.value {
                ANFValue::UpdateProp { .. } => mutates = true,
                v if is_state_output(v) => state_out = true,
                v if is_data_output(v) => data_out = true,
                ANFValue::MethodCall { method: name, .. } => {
                    if let Some(t) = privates.get(name.as_str()) {
                        if visited.insert(t.name.clone()) {
                            stack.push(&t.body);
                        }
                    }
                }
                _ => {}
            }
            stack.extend(nested(&b.value));
        }
    }
    let needs_change = mutates || state_out || data_out;
    let includes_change = crate::frontend::side_effect_summary::includes_change_output(
        needs_change,
        method.sighash_type.unwrap_or(crate::frontend::sighash_directive::SIGHASH_DEFAULT),
    );
    (needs_change, includes_change, (mutates || data_out) && !state_out)
}

fn describe(v: &ANFValue) -> String {
    match v {
        ANFValue::LoadParam { name } => format!("load_param {}", name),
        ANFValue::LoadConst { value } => match parse_const_value(value) {
            Some(ConstValue::Str(s)) => format!("load_const {}", serde_json::Value::String(s)),
            Some(ConstValue::Int(i)) => format!("load_const {}", i),
            _ => "load_const".to_string(),
        },
        ANFValue::Call { func, .. } => format!("call {}", func),
        ANFValue::BinOp { op, .. } => format!("bin_op {}", op),
        ANFValue::CheckPreimage { .. } => "check_preimage".to_string(),
        ANFValue::Assert { .. } => "assert".to_string(),
        ANFValue::DeserializeState { .. } => "deserialize_state".to_string(),
        ANFValue::GetStateScript {} => "get_state_script".to_string(),
        ANFValue::If { .. } => "if".to_string(),
        _ => "binding".to_string(),
    }
}

#[derive(Default)]
struct Matcher {
    map: HashMap<String, String>,
    mapped: HashSet<String>,
}

fn same_const(e: &serde_json::Value, a: &serde_json::Value) -> bool {
    match (parse_const_value(e), parse_const_value(a)) {
        (Some(ConstValue::Int(x)), Some(ConstValue::Int(y))) => x == y,
        (Some(ConstValue::Str(x)), Some(ConstValue::Str(y))) => x == y,
        _ => false,
    }
}

impl Matcher {
    fn r(&self, e: &str, a: &str) -> bool {
        match self.map.get(e) {
            Some(m) => m == a,
            None => e == a,
        }
    }

    fn binding(&mut self, exp: &ANFBinding, act: &ANFBinding) -> bool {
        let ok = match (&exp.value, &act.value) {
            (ANFValue::LoadParam { name: e }, ANFValue::LoadParam { name: a }) => e == a,
            (ANFValue::LoadConst { value: e }, ANFValue::LoadConst { value: a }) => same_const(e, a),
            (
                // bindingVariant is not compared (ports #170): a per-method author
                // choice the loader validates, not scaffolding.
                ANFValue::CheckPreimage { preimage: ep, sighash_flag: ef, .. },
                ANFValue::CheckPreimage { preimage: ap, sighash_flag: af, .. },
            ) => self.r(ep, ap) && ef.unwrap_or(SIGHASH_DEFAULT) == af.unwrap_or(SIGHASH_DEFAULT),
            (ANFValue::Assert { value: e, .. }, ANFValue::Assert { value: a, .. }) => self.r(e, a),
            (ANFValue::Call { func: ef, args: ea }, ANFValue::Call { func: af, args: aa }) => {
                ef == af && ea.len() == aa.len() && ea.iter().zip(aa).all(|(e, a)| self.r(e, a))
            }
            (
                ANFValue::BinOp { op: eo, left: el, right: er, result_type: et },
                ANFValue::BinOp { op: ao, left: al, right: ar, result_type: at },
            ) => {
                // An empty result_type reads as absent, as in the other tiers.
                let norm = |t: &Option<String>| t.as_deref().filter(|s| !s.is_empty()).map(str::to_string);
                eo == ao && self.r(el, al) && self.r(er, ar) && norm(et) == norm(at)
            }
            (ANFValue::DeserializeState { preimage: e }, ANFValue::DeserializeState { preimage: a }) => self.r(e, a),
            (ANFValue::GetStateScript {}, ANFValue::GetStateScript {}) => true,
            (
                ANFValue::If { cond: ec, then: et, else_branch: ee, .. },
                ANFValue::If { cond: ac, then: at, else_branch: ae, results },
            ) => {
                self.r(ec, ac) && results.is_empty() && self.sequence(et, at).is_none() && self.sequence(ee, ae).is_none()
            }
            _ => false,
        };
        if !ok || self.mapped.contains(&act.name) {
            return false;
        }
        self.map.insert(exp.name.clone(), act.name.clone());
        self.mapped.insert(act.name.clone());
        true
    }

    /// Index of the first binding that differs (a missing one included).
    fn sequence(&mut self, exp: &[ANFBinding], act: &[ANFBinding]) -> Option<usize> {
        for (i, e) in exp.iter().enumerate() {
            match act.get(i) {
                Some(a) if self.binding(e, a) => {}
                _ => return Some(i),
            }
        }
        if act.len() == exp.len() {
            None
        } else {
            Some(exp.len())
        }
    }
}

fn collect_names(bindings: &[ANFBinding], counts: &mut HashMap<String, usize>) {
    for b in bindings {
        *counts.entry(b.name.clone()).or_default() += 1;
        match &b.value {
            ANFValue::If { results, .. } => {
                for r in results {
                    *counts.entry(r.clone()).or_default() += 1;
                }
            }
            ANFValue::Loop { iter_var, .. } if !iter_var.is_empty() => {
                *counts.entry(iter_var.clone()).or_default() += 1;
            }
            _ => {}
        }
        for n in nested(&b.value) {
            collect_names(n, counts);
        }
    }
}

fn scaffold_error(method: &str, detail: String) -> String {
    format!(
        "IR validation: stateful method '{}' does not carry the scaffolding StatefulSmartContract lowering injects: {}",
        method, detail
    )
}

pub(crate) fn check_ir_stateful_scaffolding(program: &ANFProgram) -> Result<(), String> {
    let has_mutable = program.properties.iter().any(|p| !p.readonly);
    let props: HashSet<&str> = program.properties.iter().map(|p| p.name.as_str()).collect();

    for m in &program.methods {
        if !m.is_public || m.name == "constructor" {
            continue;
        }
        let (needs_change, includes_change, needs_new_amount) = shape(program, m);

        // (1) the parameters, contiguous and once each.
        let mut required: Vec<(&str, &str)> = Vec::new();
        if includes_change {
            required.push(("_changePKH", "Ripemd160"));
            required.push(("_changeAmount", "bigint"));
        }
        if needs_new_amount {
            required.push(("_newAmount", "bigint"));
        }
        required.push(("txPreimage", "SigHashPreimage"));
        let start = m.params.iter().position(|p| p.name == required[0].0);
        let params_ok = match start {
            None => false,
            Some(s) => required.iter().enumerate().all(|(i, (n, t))| {
                m.params.get(s + i).map_or(false, |p| p.name == *n && p.param_type == *t)
                    && m.params.iter().filter(|p| p.name == *n).count() == 1
            }),
        };
        if !params_ok {
            let list: Vec<String> = required.iter().map(|(n, t)| format!("{}: {}", n, t)).collect();
            return Err(format!(
                "IR validation: stateful method '{}' must declare the auto-injected parameters ({}) contiguously and once each, as StatefulSmartContract lowering does",
                m.name,
                list.join(", ")
            ));
        }

        let mut counts: HashMap<String, usize> = HashMap::new();
        collect_names(&m.body, &mut counts);
        let taken: HashSet<String> = counts.keys().cloned().collect();
        let next = std::cell::Cell::new(0usize);
        let mut matcher = Matcher::default();

        // (2) the prologue.
        let mut pro = Emitter::new(&taken, &next);
        prologue(&mut pro, m.sighash_type.unwrap_or(SIGHASH_DEFAULT), has_mutable);
        let head = &m.body[..pro.out.len().min(m.body.len())];
        if let Some(i) = matcher.sequence(&pro.out, head) {
            return Err(scaffold_error(&m.name, format!("prologue binding {} must be {}", i, describe(&pro.out[i].value))));
        }

        // (3) the continuation, over the outputs the method's own top-level
        // bindings declare (an `if` counts once, as a state output when either
        // arm holds one, else as a data output), in order.
        let rest = &m.body[pro.out.len()..];
        let mut state_out: Vec<&ANFBinding> = Vec::new();
        let mut data_out: Vec<&ANFBinding> = Vec::new();
        for b in rest {
            if is_state_output(&b.value) {
                state_out.push(b);
            } else if is_data_output(&b.value) {
                data_out.push(b);
            } else if let ANFValue::If { .. } = &b.value {
                if nested(&b.value).into_iter().any(|n| contains(n, is_state_output)) {
                    state_out.push(b);
                } else if nested(&b.value).into_iter().any(|n| contains(n, is_data_output)) {
                    data_out.push(b);
                }
            }
        }
        let state_refs: Vec<String> = state_out.iter().map(|b| b.name.clone()).collect();
        let data_refs: Vec<String> = data_out.iter().map(|b| b.name.clone()).collect();
        let mut tail = Emitter::new(&taken, &next);
        continuation(&mut tail, needs_change, includes_change, &state_refs, &data_refs);
        let offset = rest.len() as isize - tail.out.len() as isize;
        for (i, e) in tail.out.iter().enumerate() {
            let idx = offset + i as isize;
            let ok = idx >= 0 && matcher.binding(e, &rest[idx as usize]);
            if !ok {
                return Err(scaffold_error(&m.name, format!("continuation binding {} must be {}", i, describe(&e.value))));
            }
        }

        // (4) unique, unshadowed names for what the scaffolding binds or
        // commits to. A binding's own arms may reuse its name (an
        // output-carrying `if` is named after its arm's last binding).
        let params: HashSet<&str> = m.params.iter().map(|p| p.name.as_str()).collect();
        let mut checked: Vec<&ANFBinding> = Vec::new();
        fn preorder<'b>(bs: &'b [ANFBinding], out: &mut Vec<&'b ANFBinding>) {
            for b in bs {
                out.push(b);
                for n in nested(&b.value) {
                    preorder(n, out);
                }
            }
        }
        preorder(head, &mut checked);
        if offset >= 0 {
            preorder(&rest[offset as usize..], &mut checked);
        }
        checked.extend(state_out.iter().copied());
        checked.extend(data_out.iter().copied());
        for b in checked {
            let mut inner: HashMap<String, usize> = HashMap::new();
            for n in nested(&b.value) {
                collect_names(n, &mut inner);
            }
            let outside = counts.get(&b.name).copied().unwrap_or(0) - inner.get(&b.name).copied().unwrap_or(0);
            if outside != 1 || props.contains(b.name.as_str()) || params.contains(b.name.as_str()) {
                return Err(format!(
                    "IR validation: stateful method '{}' must bind '{}' exactly once, under a name no property or parameter uses: the injected scaffolding binds it or the continuation commits to it",
                    m.name, b.name
                ));
            }
        }
    }
    Ok(())
}
