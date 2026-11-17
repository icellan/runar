//! D15: the preimage rules on `--ir` input. Port of
//! packages/runar-compiler/src/passes/ir-preimage-rules.ts (see its header for
//! the full rule and for what ANF cannot carry). `--ir` skips the frontend, so
//! D9 (no SigHashPreimage property), GK-GAP-010 (a public method's
//! SigHashPreimage parameter is asserted on every path) and D14 (an extractor
//! reads only a checked preimage) are re-derived here, failing closed.

use std::collections::{HashMap, HashSet};

use super::{ANFBinding, ANFMethod, ANFProgram, ANFValue};
use crate::frontend::preimage_checked::{
    preimage_not_checked_message, unchecked_preimage_arg_message, PREIMAGE_EXTRACTORS,
};
use crate::frontend::validator::preimage_property_message;

const SHP: &str = "SigHashPreimage";

/// `None` stands for "everything" (what a constant-false arm implies).
type Checks = Option<HashSet<String>>;

fn union(a: Checks, b: Checks) -> Checks {
    match (a, b) {
        (Some(mut a), Some(b)) => {
            a.extend(b);
            Some(a)
        }
        _ => None,
    }
}

fn intersect(a: Checks, b: Checks) -> Checks {
    match (a, b) {
        (None, b) => b,
        (a, None) => a,
        (Some(a), Some(b)) => Some(a.intersection(&b).cloned().collect()),
    }
}

fn ref_target(v: &ANFValue) -> Option<&str> {
    match v {
        ANFValue::LoadConst { value: serde_json::Value::String(s) } => s.strip_prefix("@ref:"),
        _ => None,
    }
}

struct View<'a> {
    defs: HashMap<&'a str, &'a ANFValue>,
    dup: HashSet<&'a str>,
    shp: HashSet<&'a str>,
    implicit: bool,
}

impl<'a> View<'a> {
    fn new(m: &'a ANFMethod, implicit_tx: bool) -> Self {
        let mut v = View { defs: HashMap::new(), dup: HashSet::new(), shp: HashSet::new(), implicit: false };
        v.collect(&m.body);
        for p in &m.params {
            if p.param_type == SHP {
                v.shp.insert(p.name.as_str());
            }
        }
        let own = m.params.iter().any(|p| p.name == "txPreimage");
        v.implicit = !m.is_public && implicit_tx && !own;
        v
    }

    fn collect(&mut self, bindings: &'a [ANFBinding]) {
        for b in bindings {
            if self.defs.contains_key(b.name.as_str()) {
                self.dup.insert(b.name.as_str());
            }
            self.defs.insert(b.name.as_str(), &b.value);
            match &b.value {
                ANFValue::If { then, else_branch, .. } => {
                    self.collect(then);
                    self.collect(else_branch);
                }
                ANFValue::Loop { body, .. } => self.collect(body),
                _ => {}
            }
        }
    }

    fn resolve(&self, start: Option<&str>) -> Option<String> {
        let mut name = start?;
        let mut seen = HashSet::new();
        loop {
            if self.dup.contains(name) || !seen.insert(name) {
                return None;
            }
            let v = self.defs.get(name)?;
            match v {
                ANFValue::LoadParam { name: p } => {
                    if self.shp.contains(p.as_str()) || (self.implicit && p == "txPreimage") {
                        return Some(p.clone());
                    }
                    return None;
                }
                ANFValue::LoadProp { name: p, .. } => {
                    return if self.implicit && p == "txPreimage" { Some(p.clone()) } else { None };
                }
                _ => name = ref_target(v)?,
            }
        }
    }

    fn truth_checks(&self, name: &str, seen: &mut HashSet<String>) -> Checks {
        if self.dup.contains(name) || !seen.insert(name.to_string()) {
            return Some(HashSet::new());
        }
        let Some(v) = self.defs.get(name) else { return Some(HashSet::new()) };
        match v {
            ANFValue::CheckPreimage { preimage, .. } => {
                Some(self.resolve(Some(preimage.as_str())).into_iter().collect())
            }
            ANFValue::LoadConst { value: serde_json::Value::Bool(false) } => None,
            ANFValue::LoadConst { .. } => match ref_target(v) {
                Some(next) => self.truth_checks(next, seen),
                None => Some(HashSet::new()),
            },
            ANFValue::If { cond, then, else_branch, results, .. } => {
                if !results.is_empty() || then.is_empty() || else_branch.is_empty() {
                    return Some(HashSet::new());
                }
                let t = union(
                    self.truth_checks(cond, seen),
                    self.truth_checks(&then[then.len() - 1].name, seen),
                );
                intersect(t, self.truth_checks(&else_branch[else_branch.len() - 1].name, seen))
            }
            _ => Some(HashSet::new()),
        }
    }
}

struct Rules<'a> {
    privates: HashMap<&'a str, &'a ANFMethod>,
    implicit_tx: bool,
    /// Keyed by method identity (address), never by name.
    memo: HashMap<*const ANFMethod, HashSet<String>>,
}

impl<'a> Rules<'a> {
    fn must_checked(&mut self, m: &'a ANFMethod, stack: &HashSet<*const ANFMethod>) -> HashSet<String> {
        let key = m as *const ANFMethod;
        if let Some(r) = self.memo.get(&key) {
            return r.clone();
        }
        if stack.contains(&key) {
            return HashSet::new();
        }
        let mv = View::new(m, self.implicit_tx);
        let mut inner = stack.clone();
        inner.insert(key);
        let result = self.walk(&mv, &m.body, HashSet::new(), &inner);
        self.memo.insert(key, result.clone());
        result
    }

    fn walk(
        &mut self,
        mv: &View<'a>,
        bindings: &'a [ANFBinding],
        done_in: HashSet<String>,
        inner: &HashSet<*const ANFMethod>,
    ) -> HashSet<String> {
        let mut done = done_in;
        for b in bindings {
            match &b.value {
                ANFValue::Assert { value, .. } => {
                    if let Some(c) = mv.truth_checks(value, &mut HashSet::new()) {
                        done.extend(c);
                    }
                }
                ANFValue::If { then, else_branch, .. } => {
                    let t = self.walk(mv, then, done.clone(), inner);
                    let e = self.walk(mv, else_branch, done.clone(), inner);
                    done = t.intersection(&e).cloned().collect();
                }
                ANFValue::MethodCall { method, args, .. } => {
                    if let Some(target) = self.privates.get(method.as_str()).copied() {
                        let checked = self.must_checked(target, inner);
                        for (i, p) in target.params.iter().enumerate() {
                            if checked.contains(&p.name) {
                                if let Some(o) = mv.resolve(args.get(i).map(|s| s.as_str())) {
                                    done.insert(o);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        done
    }
}

fn visit(
    mv: &View<'_>,
    privates: &HashMap<&str, &ANFMethod>,
    bindings: &[ANFBinding],
    errors: &mut Vec<String>,
) {
    for b in bindings {
        match &b.value {
            ANFValue::Call { func, args } if PREIMAGE_EXTRACTORS.contains(&func.as_str()) => {
                if mv.resolve(args.first().map(|s| s.as_str())).is_none() {
                    errors.push(unchecked_preimage_arg_message(func));
                }
            }
            ANFValue::MethodCall { method, args, .. } => {
                if let Some(target) = privates.get(method.as_str()) {
                    if target.params.iter().enumerate().any(|(i, p)| {
                            p.param_type == SHP && mv.resolve(args.get(i).map(|s| s.as_str())).is_none()
                        })
                    {
                        errors.push(unchecked_preimage_arg_message(&target.name));
                    }
                }
            }
            ANFValue::If { then, else_branch, .. } => {
                visit(mv, privates, then, errors);
                visit(mv, privates, else_branch, errors);
            }
            ANFValue::Loop { body, .. } => visit(mv, privates, body, errors),
            _ => {}
        }
    }
}

pub fn preimage_rule_errors(program: &ANFProgram) -> Vec<String> {
    let mut errors: Vec<String> = program
        .properties
        .iter()
        .filter(|p| p.prop_type == SHP)
        .map(|p| preimage_property_message(&p.name))
        .collect();
    // A method_call resolves exactly as stack lowering inlines it: to the LAST
    // non-public, non-constructor method of that name (codegen/stack.rs). The
    // loader refuses duplicate names first; this never relies on that alone.
    let privates: HashMap<&str, &ANFMethod> = program
        .methods
        .iter()
        .filter(|m| !m.is_public && m.name != "constructor")
        .map(|m| (m.name.as_str(), m))
        .collect();
    let publics: Vec<&ANFMethod> =
        program.methods.iter().filter(|m| m.is_public && m.name != "constructor").collect();
    let implicit_tx = !publics.is_empty()
        && publics.iter().all(|m| m.params.iter().any(|p| p.name == "txPreimage" && p.param_type == SHP))
        && !program.properties.iter().any(|p| p.name == "txPreimage");
    let mut rules = Rules { privates: privates.clone(), implicit_tx, memo: HashMap::new() };
    for m in &program.methods {
        if m.name == "constructor" {
            continue;
        }
        let mv = View::new(m, implicit_tx);
        visit(&mv, &privates, &m.body, &mut errors);
        if m.is_public {
            let done = rules.must_checked(m, &HashSet::new());
            for p in &m.params {
                if p.param_type == SHP && !done.contains(&p.name) {
                    errors.push(preimage_not_checked_message(&m.name, &p.name));
                }
            }
        }
    }
    errors
}

/// Every D9 / GK-GAP-010 / D14 violation, joined, or `Ok`.
pub fn assert_preimage_rules(program: &ANFProgram) -> Result<(), String> {
    let errors = preimage_rule_errors(program);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("IR validation: {}", errors.join("; ")))
    }
}

/// GK-BUG-015's shared text on the IR path: a repeated method name, refused
/// before anything looks a method up by name (the source validator refuses
/// it; `--ir` did not, so two bodies could share a name).
pub fn assert_unique_method_names(program: &ANFProgram) -> Result<(), String> {
    let mut seen = HashSet::new();
    for m in &program.methods {
        if !seen.insert(m.name.as_str()) {
            return Err(format!(
                "IR validation: method '{}' is already declared in this contract and cannot be re-declared",
                m.name
            ));
        }
    }
    Ok(())
}
