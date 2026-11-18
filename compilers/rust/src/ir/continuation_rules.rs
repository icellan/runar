//! D18 on the `--ir` path. `--ir` skips typecheck, where the source path
//! refuses a public stateful method that declares its own outputs and has a
//! path that writes state but reaches no `addOutput` (that write would be
//! dropped and the contract's satoshis would leave with the spend).
//! Re-derived from the ANF, per path, through `if` arms, loop bodies and
//! `method_call`s to private methods. Mirrors `assertIrNoDroppedContinuation` in
//! `packages/runar-compiler/src/passes/continuation-rules.ts`. Run for
//! StatefulSmartContract programs after the N-101 scaffolding check.

use std::collections::{HashMap, HashSet};

use super::{ANFBinding, ANFMethod, ANFProgram, ANFValue};
use crate::frontend::continuation_rules::{dropped_continuation_message, PathSet, PATH_A, PATH_W};

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

/// The per-path rule on ANF: `update_prop` = state write, `add_output` =
/// addOutput, `add_raw_output` / `add_output` = a declared output (suppresses
/// the auto-continuation). `if` unions its arms, a loop body unions with
/// skipping it, a `method_call` to a private method composes with that
/// method's exits.
fn drops(method: &ANFMethod, privates: &HashMap<&str, &ANFMethod>) -> bool {
    if !declares(&method.body, privates, &mut HashSet::new()) {
        return false;
    }
    let mut exits_of = HashMap::new();
    run(&method.body, PathSet::FRESH, privates, &mut exits_of, &mut HashSet::new()).dropped()
}

fn declares<'a>(bindings: &'a [ANFBinding], privates: &HashMap<&str, &'a ANFMethod>, seen: &mut HashSet<&'a str>) -> bool {
    bindings.iter().any(|b| match &b.value {
        ANFValue::AddOutput { .. } | ANFValue::AddRawOutput { .. } => true,
        ANFValue::MethodCall { method, .. } => match privates.get(method.as_str()) {
            Some(t) if seen.insert(t.name.as_str()) => declares(&t.body, privates, seen),
            _ => false,
        },
        ANFValue::If { then, else_branch, .. } => {
            declares(then, privates, seen) || declares(else_branch, privates, seen)
        }
        ANFValue::Loop { body, .. } => declares(body, privates, seen),
        _ => false,
    })
}

fn run<'a>(
    bindings: &'a [ANFBinding],
    states: PathSet,
    privates: &HashMap<&str, &'a ANFMethod>,
    exits_of: &mut HashMap<&'a str, PathSet>,
    in_progress: &mut HashSet<&'a str>,
) -> PathSet {
    let mut s = states;
    for b in bindings {
        match &b.value {
            ANFValue::UpdateProp { .. } => s = s.or_all(PATH_W),
            ANFValue::AddOutput { .. } => s = s.or_all(PATH_A),
            ANFValue::MethodCall { method, .. } => {
                if let Some(t) = privates.get(method.as_str()) {
                    let name = t.name.as_str();
                    let ex = match exits_of.get(name) {
                        Some(ex) => *ex,
                        None if in_progress.contains(name) => PathSet::FRESH,
                        None => {
                            in_progress.insert(name);
                            let ex = run(&t.body, PathSet::FRESH, privates, exits_of, in_progress);
                            in_progress.remove(name);
                            exits_of.insert(name, ex);
                            ex
                        }
                    };
                    s = s.compose(ex);
                }
            }
            ANFValue::If { then, else_branch, .. } => {
                let t = run(then, s, privates, exits_of, in_progress);
                let e = run(else_branch, s, privates, exits_of, in_progress);
                s = t.union(e);
            }
            ANFValue::Loop { body, .. } => s = s.union(run(body, s, privates, exits_of, in_progress)),
            _ => {}
        }
    }
    s
}
