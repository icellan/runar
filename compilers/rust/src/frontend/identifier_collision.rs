//! F-017 — the identifier-collision rule.
//!
//! Five surfaces rename identifiers on the way into the AST: `.runar.py`,
//! `.runar.rb`, `.runar.rs`, `.runar.move` (snake_case -> camelCase) and
//! `.runar.go` (PascalCase -> camelCase). None of those mappings is injective:
//! `tmp` and `tmp_`, `a_b` and `aB`, `_tmp` and `tmp` (.py/.rb), `Tmp` and
//! `tmp` (.go) each land on one Rúnar name. Before this rule both spellings
//! were bound to ONE variable, so `tmp = n + 1; tmp_ = n + 2;
//! assert_(tmp == tmp_)` — always false in the source language — compiled to a
//! self-comparison that always passes.
//!
//! While parsing one contract, the surface parser records (source spelling,
//! Rúnar name) for every identifier it DECLARES: properties / struct fields,
//! method names (not the constructor), parameters (not receivers), locals at
//! every declaration or bare-name assignment target, and loop variables. If
//! two recorded pairs share a Rúnar name but differ in spelling, the contract
//! is refused with exactly one error whose text is identical in all seven
//! tiers. Mirrors `identifierCollisionMessage` in
//! packages/runar-compiler/src/passes/snake-to-camel.ts.

use std::collections::{BTreeMap, BTreeSet};

use super::diagnostic::Diagnostic;

/// The (source spelling, Rúnar name) pairs declared by one contract.
#[derive(Default)]
pub struct DeclaredIdents {
    decls: Vec<(String, String)>,
}

impl DeclaredIdents {
    /// Record one declared identifier and return its Rúnar name.
    pub fn declare(&mut self, raw: &str, name: String) -> String {
        self.decls.push((raw.to_string(), name.clone()));
        name
    }

    /// The single F-017 error, if any.
    pub fn collision_diagnostic(&self) -> Option<Diagnostic> {
        identifier_collision_message(&self.decls).map(|m| Diagnostic::error(m, None))
    }
}

/// The collision with the smallest Rúnar name and, for it, the two smallest
/// source spellings (byte order), so the report does not depend on
/// declaration order. `None` when every name has one spelling.
pub fn identifier_collision_message(decls: &[(String, String)]) -> Option<String> {
    let mut spellings: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (raw, name) in decls {
        spellings.entry(name.as_str()).or_default().insert(raw.as_str());
    }
    spellings.iter().find(|(_, set)| set.len() >= 2).map(|(name, set)| {
        let mut it = set.iter();
        let a = it.next().unwrap();
        let b = it.next().unwrap();
        format!("identifier collision: '{}' and '{}' both convert to '{}'; rename one of them", a, b, name)
    })
}
