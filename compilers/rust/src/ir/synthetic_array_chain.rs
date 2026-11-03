//! N-096 — the `syntheticArrayChain` validity rule for `--ir` input. Port of
//! `packages/runar-compiler/src/ir/synthetic-array-chain.ts`: same rule, same
//! order, same words (`conformance/negatives/ir-synthetic-array-chain.test.ts`).
//!
//! 1. at most `MAX_SYNTHETIC_ARRAY_DEPTH` levels (the regrouper's 1024 passes
//!    are the only nesting bound the pipeline has);
//! 2. every level has `0 <= index < length`;
//! 3. level k's base is level k-1's `<base>__<index>`, and the property is
//!    named `<innermost base>__<innermost index>`;
//! 4. the leaves sharing a root are exactly one expansion: contiguous,
//!    row-major from element 0, one type and one list of level lengths, and
//!    complete.

use std::collections::HashSet;

use super::{ANFProgram, ANFSyntheticArrayLevel};

/// The deepest chain the regrouper's 1024-pass cap can consume.
pub const MAX_SYNTHETIC_ARRAY_DEPTH: usize = 1023;

fn refuse(prop: &str, detail: &str) -> String {
    format!("IR validation: malformed syntheticArrayChain on property '{}': {}", prop, detail)
}

struct Family {
    root: String,
    typ: String,
    lengths: Vec<usize>,
    tuple: Vec<usize>,
    last: String,
}

fn leaf_name(root: &str, tuple: &[usize]) -> String {
    let mut s = root.to_string();
    for i in tuple {
        s.push_str("__");
        s.push_str(&i.to_string());
    }
    s
}

impl Family {
    fn complete(&self) -> bool {
        self.tuple.iter().zip(&self.lengths).all(|(i, l)| *i + 1 == *l)
    }

    fn next(&self) -> Vec<usize> {
        let mut t = self.tuple.clone();
        for k in (0..t.len()).rev() {
            if t[k] + 1 < self.lengths[k] {
                t[k] += 1;
                return t;
            }
            t[k] = 0;
        }
        t
    }
}

fn expects(root: &str, typ: &str, lengths: &[usize], tuple: &[usize]) -> String {
    let ls: Vec<String> = lengths.iter().map(|l| l.to_string()).collect();
    format!(
        "'{}' expects its element '{}' here (type {}, level lengths [{}])",
        root,
        leaf_name(root, tuple),
        typ,
        ls.join(", ")
    )
}

fn check_levels(name: &str, chain: &[ANFSyntheticArrayLevel]) -> Result<(), String> {
    if chain.len() > MAX_SYNTHETIC_ARRAY_DEPTH {
        return Err(refuse(
            name,
            &format!("{} levels exceed the limit of {}", chain.len(), MAX_SYNTHETIC_ARRAY_DEPTH),
        ));
    }
    for (k, lvl) in chain.iter().enumerate() {
        if lvl.index >= lvl.length {
            return Err(refuse(
                name,
                &format!(
                    "level {} has index {} and length {}; expand-fixed-arrays writes 0 <= index < length",
                    k, lvl.index, lvl.length
                ),
            ));
        }
        if k > 0 {
            let want = format!("{}__{}", chain[k - 1].base, chain[k - 1].index);
            if lvl.base != want {
                return Err(refuse(
                    name,
                    &format!("level {} has base '{}'; expand-fixed-arrays writes '{}'", k, lvl.base, want),
                ));
            }
        }
    }
    let inner = &chain[chain.len() - 1];
    let want = format!("{}__{}", inner.base, inner.index);
    if name != want {
        return Err(refuse(
            name,
            &format!(
                "its innermost level is element {} of '{}'; expand-fixed-arrays names that property '{}'",
                inner.index, inner.base, want
            ),
        ));
    }
    Ok(())
}

fn close(open: &mut Option<Family>) -> Result<(), String> {
    if let Some(f) = open.take() {
        if !f.complete() {
            return Err(refuse(
                &f.last,
                &format!("'{}' ends here, before its element '{}'", f.root, leaf_name(&f.root, &f.next())),
            ));
        }
    }
    Ok(())
}

/// The shared diagnostic for the first chain the rule refuses.
pub fn assert_synthetic_array_chains(program: &ANFProgram) -> Result<(), String> {
    let mut open: Option<Family> = None;
    let mut seen: HashSet<String> = HashSet::new();
    let empty: Vec<ANFSyntheticArrayLevel> = Vec::new();

    for prop in &program.properties {
        let chain = prop.synthetic_array_chain.as_ref().unwrap_or(&empty);
        if let Some(f) = &open {
            if chain.is_empty() || chain[0].base != f.root {
                close(&mut open)?;
            }
        }
        if chain.is_empty() {
            continue;
        }
        check_levels(&prop.name, chain)?;
        let tuple: Vec<usize> = chain.iter().map(|l| l.index).collect();
        let lengths: Vec<usize> = chain.iter().map(|l| l.length).collect();

        if let Some(f) = open.as_mut() {
            if f.complete() {
                return Err(refuse(&prop.name, &format!("'{}' already ended before this property", f.root)));
            }
            let want = f.next();
            if prop.prop_type != f.typ || lengths != f.lengths || tuple != want {
                return Err(refuse(&prop.name, &expects(&f.root, &f.typ, &f.lengths, &want)));
            }
            f.tuple = want;
            f.last = prop.name.clone();
            continue;
        }

        let root = chain[0].base.clone();
        if seen.contains(&root) {
            return Err(refuse(&prop.name, &format!("'{}' already ended before this property", root)));
        }
        let start = vec![0usize; chain.len()];
        if tuple != start {
            return Err(refuse(&prop.name, &expects(&root, &prop.prop_type, &lengths, &start)));
        }
        seen.insert(root.clone());
        open = Some(Family { root, typ: prop.prop_type.clone(), lengths, tuple, last: prop.name.clone() });
    }
    close(&mut open)
}
