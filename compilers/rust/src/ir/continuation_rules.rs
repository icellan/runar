//! D18 on the `--ir` path. `--ir` skips typecheck, where the source path
//! refuses a public stateful method that writes state and declares raw
//! outputs but no `addOutput` (its state write would be dropped and the
//! contract's satoshis would leave with the spend). Re-derived from the ANF:
//! `update_prop` = state write, `add_output` / `add_raw_output` = declared
//! outputs, at any depth (if then/else, loop body) and through `method_call`
//! to private methods. Mirrors `assertIrNoDroppedContinuation` in
//! `packages/runar-compiler/src/passes/continuation-rules.ts`. Run for
//! StatefulSmartContract programs after the N-101 scaffolding check.

use std::collections::{HashMap, HashSet};

use super::{ANFBinding, ANFMethod, ANFProgram, ANFValue};
use crate::frontend::continuation_rules::dropped_continuation_message;

pub fn assert_no_dropped_continuation(program: &ANFProgram) -> Result<(), String> {
    let privates: HashMap<&str, &ANFMethod> = program
        .methods
        .iter()
        .filter(|m| !m.is_public && m.name != "constructor")
        .map(|m| (m.name.as_str(), m))
        .collect();
    for m in &program.methods {
        if m.is_public && m.name != "constructor" && drops(m, &privates) {
            return Err(dropped_continuation_message(&m.name));
        }
    }
    Ok(())
}

#[derive(Default)]
struct Seen {
    writes: bool,
    raw: bool,
    add: bool,
}

fn drops(method: &ANFMethod, privates: &HashMap<&str, &ANFMethod>) -> bool {
    let mut seen = Seen::default();
    let mut visited = HashSet::new();
    walk(&method.body, privates, &mut visited, &mut seen);
    seen.writes && seen.raw && !seen.add
}

fn walk<'a>(
    bindings: &'a [ANFBinding],
    privates: &HashMap<&str, &'a ANFMethod>,
    visited: &mut HashSet<&'a str>,
    seen: &mut Seen,
) {
    for b in bindings {
        match &b.value {
            ANFValue::UpdateProp { .. } => seen.writes = true,
            ANFValue::AddRawOutput { .. } => seen.raw = true,
            ANFValue::AddOutput { .. } => seen.add = true,
            ANFValue::MethodCall { method, .. } => {
                if let Some(target) = privates.get(method.as_str()) {
                    if visited.insert(target.name.as_str()) {
                        walk(&target.body, privates, visited, seen);
                    }
                }
            }
            ANFValue::If { then, else_branch, .. } => {
                walk(then, privates, visited, seen);
                walk(else_branch, privates, visited, seen);
            }
            ANFValue::Loop { body, .. } => walk(body, privates, visited, seen),
            _ => {}
        }
    }
}
