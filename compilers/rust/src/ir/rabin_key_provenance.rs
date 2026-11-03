//! N-205 (b) — F-286's verifyRabinSig key-provenance rule, and N-205 (a)'s
//! rule for writes to a key property, re-asserted on `--ir` input. Port of
//! `packages/runar-compiler/src/ir/rabin-key-provenance.ts`: same rule, same
//! order, same words (`conformance/negatives/ir-rabin-key-provenance.test.ts`).
//!
//! A ref is trusted when EVERY binding of that name in the method (flattened
//! pre-order: a binding, then its then / else / body) is a `load_prop`, an
//! integer `load_const`, a `load_const "@ref:<x>"` with `<x>` trusted, a
//! private method's `load_param` that every `method_call` site (at least one)
//! binds to a trusted ref (least fixed point), or an `if` with no `results`
//! whose arms are both non-empty and end in a trusted binding. A name with no
//! binding, or one reached again while being resolved, is untrusted.
//! KEY properties: the `load_prop` names a verifyRabinSig 4th argument can
//! come from, closed under "a trusted value written into a key property comes
//! from it". Writes (non-constructor methods): `update_prop`, and
//! `add_output.stateValues[i]` for the i-th non-readonly property. Per method
//! in program order: every untrusted verifyRabinSig 4th argument, then every
//! untrusted write of a MUTABLE key property; the first refusal wins.

use std::collections::{HashMap, HashSet};

use super::{parse_const_value, ANFBinding, ANFMethod, ANFProgram, ANFValue, ConstValue};
use crate::frontend::validator::{rabin_key_write_message, RABIN_PUBKEY_PROVENANCE_MESSAGE};

fn flatten<'a>(bindings: &'a [ANFBinding], out: &mut Vec<&'a ANFBinding>) {
    for b in bindings {
        out.push(b);
        match &b.value {
            ANFValue::If { then, else_branch, .. } => {
                flatten(then, out);
                flatten(else_branch, out);
            }
            ANFValue::Loop { body, .. } => flatten(body, out),
            _ => {}
        }
    }
}

fn is_private(m: &ANFMethod) -> bool {
    !m.is_public && m.name != "constructor"
}

struct Ctx<'a> {
    methods: &'a [ANFMethod],
    by_name: Vec<HashMap<&'a str, Vec<&'a ANFValue>>>,
    private_idx: HashMap<&'a str, usize>,
    /// private method name -> (args, caller method index)
    call_sites: HashMap<&'a str, Vec<(&'a [String], usize)>>,
    trusted_params: HashMap<&'a str, HashSet<usize>>,
}

fn alias_target(value: &serde_json::Value) -> Option<String> {
    match parse_const_value(value) {
        Some(ConstValue::Str(s)) => s.strip_prefix("@ref:").map(|t| t.to_string()),
        _ => None,
    }
}

fn is_trusted(ctx: &Ctx, ref_name: &str, mi: usize, visiting: &mut HashSet<String>) -> bool {
    let values = match ctx.by_name[mi].get(ref_name) {
        Some(v) => v,
        None => return false,
    };
    if !visiting.insert(ref_name.to_string()) {
        return false;
    }
    let m = &ctx.methods[mi];
    let ok = values.iter().all(|v| match v {
        ANFValue::LoadProp { .. } => true,
        ANFValue::LoadConst { value } => match parse_const_value(value) {
            Some(ConstValue::Int(_)) => true,
            _ => match alias_target(value) {
                Some(t) => is_trusted(ctx, &t, mi, visiting),
                None => false,
            },
        },
        ANFValue::LoadParam { name } => {
            if !is_private(m) {
                return false;
            }
            match m.params.iter().position(|p| &p.name == name) {
                Some(idx) => ctx.trusted_params.get(m.name.as_str()).map_or(false, |s| s.contains(&idx)),
                None => false,
            }
        }
        ANFValue::If { then, else_branch, results, .. } => {
            if !results.is_empty() {
                return false;
            }
            match (then.last(), else_branch.last()) {
                (Some(a), Some(b)) => {
                    is_trusted(ctx, &a.name, mi, visiting) && is_trusted(ctx, &b.name, mi, visiting)
                }
                _ => false,
            }
        }
        _ => false,
    });
    visiting.remove(ref_name);
    ok
}

fn sources_of(ctx: &Ctx, ref_name: &str, mi: usize, out: &mut HashSet<String>, visiting: &mut HashSet<(usize, String)>) {
    if !visiting.insert((mi, ref_name.to_string())) {
        return;
    }
    let m = &ctx.methods[mi];
    for v in ctx.by_name[mi].get(ref_name).map(|v| v.as_slice()).unwrap_or(&[]) {
        match v {
            ANFValue::LoadProp { name, .. } => {
                out.insert(name.clone());
            }
            ANFValue::LoadConst { value } => {
                if let Some(t) = alias_target(value) {
                    sources_of(ctx, &t, mi, out, visiting);
                }
            }
            ANFValue::If { then, else_branch, .. } => {
                for arm in [then, else_branch] {
                    if let Some(last) = arm.last() {
                        sources_of(ctx, &last.name, mi, out, visiting);
                    }
                }
            }
            ANFValue::LoadParam { name } if is_private(m) => {
                if let Some(idx) = m.params.iter().position(|p| &p.name == name) {
                    for (args, caller) in ctx.call_sites.get(m.name.as_str()).map(|v| v.as_slice()).unwrap_or(&[]) {
                        if let Some(a) = args.get(idx) {
                            sources_of(ctx, a, *caller, out, visiting);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

pub fn assert_rabin_key_provenance(program: &ANFProgram) -> Result<(), String> {
    let methods = program.methods.as_slice();
    let flat: Vec<Vec<&ANFBinding>> = methods
        .iter()
        .map(|m| {
            let mut list = Vec::new();
            flatten(&m.body, &mut list);
            list
        })
        .collect();
    let by_name = flat
        .iter()
        .map(|list| {
            let mut names: HashMap<&str, Vec<&ANFValue>> = HashMap::new();
            for b in list {
                names.entry(b.name.as_str()).or_default().push(&b.value);
            }
            names
        })
        .collect();
    let mut private_idx: HashMap<&str, usize> = HashMap::new();
    for (i, m) in methods.iter().enumerate() {
        if is_private(m) {
            private_idx.insert(m.name.as_str(), i);
        }
    }
    let mut call_sites: HashMap<&str, Vec<(&[String], usize)>> =
        private_idx.keys().map(|k| (*k, Vec::new())).collect();
    for (mi, list) in flat.iter().enumerate() {
        for b in list {
            if let ANFValue::MethodCall { method, args, .. } = &b.value {
                if let Some(sites) = call_sites.get_mut(method.as_str()) {
                    sites.push((args.as_slice(), mi));
                }
            }
        }
    }
    let trusted_params = private_idx.keys().map(|k| (*k, HashSet::new())).collect();
    let mut ctx = Ctx { methods, by_name, private_idx, call_sites, trusted_params };

    // Least fixed point over private-method parameters. Iterate in program
    // order so the result does not depend on hash order.
    let private_names: Vec<&str> = methods.iter().filter(|m| is_private(m)).map(|m| m.name.as_str()).collect();
    let mut changed = true;
    while changed {
        changed = false;
        for name in &private_names {
            let mi = ctx.private_idx[name];
            let sites = ctx.call_sites[name].clone();
            if sites.is_empty() {
                continue;
            }
            for i in 0..methods[mi].params.len() {
                if ctx.trusted_params[name].contains(&i) {
                    continue;
                }
                let ok = sites.iter().all(|(args, caller)| match args.get(i) {
                    Some(a) => is_trusted(&ctx, a, *caller, &mut HashSet::new()),
                    None => false,
                });
                if ok {
                    ctx.trusted_params.get_mut(name).unwrap().insert(i);
                    changed = true;
                }
            }
        }
    }

    let mut key_props: HashSet<String> = HashSet::new();
    for (mi, list) in flat.iter().enumerate() {
        for b in list {
            if let ANFValue::Call { func, args } = &b.value {
                if func == "verifyRabinSig" && args.len() >= 4 {
                    sources_of(&ctx, &args[3], mi, &mut key_props, &mut HashSet::new());
                }
            }
        }
    }

    let mutable_props: Vec<&str> =
        program.properties.iter().filter(|p| !p.readonly).map(|p| p.name.as_str()).collect();
    let mut writes: Vec<(String, &str, usize)> = Vec::new();
    for (mi, list) in flat.iter().enumerate() {
        if methods[mi].name == "constructor" {
            continue;
        }
        for b in list {
            match &b.value {
                ANFValue::UpdateProp { name, value } => writes.push((name.clone(), value.as_str(), mi)),
                ANFValue::AddOutput { state_values, .. } => {
                    for (i, v) in state_values.iter().enumerate() {
                        if let Some(p) = mutable_props.get(i) {
                            writes.push((p.to_string(), v.as_str(), mi));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    loop {
        let before = key_props.len();
        for (prop, value, mi) in &writes {
            if key_props.contains(prop) && is_trusted(&ctx, value, *mi, &mut HashSet::new()) {
                sources_of(&ctx, value, *mi, &mut key_props, &mut HashSet::new());
            }
        }
        if key_props.len() == before {
            break;
        }
    }

    for (mi, list) in flat.iter().enumerate() {
        let m = &methods[mi];
        for b in list {
            if let ANFValue::Call { func, args } = &b.value {
                if func == "verifyRabinSig" && args.len() >= 4 && !is_trusted(&ctx, &args[3], mi, &mut HashSet::new()) {
                    return Err(format!("IR validation: method '{}': {}", m.name, RABIN_PUBKEY_PROVENANCE_MESSAGE));
                }
            }
        }
        for (prop, value, wmi) in &writes {
            if *wmi != mi || !key_props.contains(prop) || !mutable_props.contains(&prop.as_str()) {
                continue;
            }
            if !is_trusted(&ctx, value, mi, &mut HashSet::new()) {
                return Err(format!("IR validation: method '{}': {}", m.name, rabin_key_write_message(prop)));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(key_value: serde_json::Value) -> ANFProgram {
        let json = serde_json::json!({
            "contractName": "C",
            "parentClass": "SmartContract",
            "properties": [{ "name": "pk", "type": "RabinPubKey", "readonly": true }],
            "methods": [{
                "name": "settle",
                "isPublic": true,
                "params": [
                    { "name": "msg", "type": "ByteString" },
                    { "name": "sig", "type": "RabinSig" },
                    { "name": "padding", "type": "ByteString" },
                    { "name": "n", "type": "RabinPubKey" }
                ],
                "body": [
                    { "name": "t0", "value": { "kind": "load_param", "name": "msg" } },
                    { "name": "t1", "value": { "kind": "load_param", "name": "sig" } },
                    { "name": "t2", "value": { "kind": "load_param", "name": "padding" } },
                    { "name": "t3", "value": key_value },
                    { "name": "t4", "value": { "kind": "call", "func": "verifyRabinSig", "args": ["t0", "t1", "t2", "t3"] } },
                    { "name": "t5", "value": { "kind": "assert", "value": "t4" } }
                ]
            }]
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn n205_ir_key_from_load_param_is_refused() {
        let err = assert_rabin_key_provenance(&program(serde_json::json!({ "kind": "load_param", "name": "n" })))
            .unwrap_err();
        assert_eq!(err, format!("IR validation: method 'settle': {}", RABIN_PUBKEY_PROVENANCE_MESSAGE));
    }

    #[test]
    fn n205_ir_key_from_load_prop_or_integer_is_accepted() {
        assert!(assert_rabin_key_provenance(&program(serde_json::json!({ "kind": "load_prop", "name": "pk" }))).is_ok());
        assert!(assert_rabin_key_provenance(&program(serde_json::json!({ "kind": "load_const", "value": 1000003 }))).is_ok());
        assert!(assert_rabin_key_provenance(&program(serde_json::json!({ "kind": "load_const", "value": "1000003n" }))).is_ok());
        assert!(assert_rabin_key_provenance(&program(serde_json::json!({ "kind": "load_const", "value": "01" }))).is_err());
    }
}
