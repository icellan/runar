// N-108 — the `Sha256Digest` alias on the Rust-DSL surface.
//
// `Sha256DigestAlias.runar.ts` is this fixture's `.runar.ts` sibling and gates
// the same alias on the TypeScript surface (N-104b). The alias is a per-SURFACE
// rule, not a per-tier one, so a `.runar.ts` fixture proves nothing about
// `.runar.rs`: the full 9-surface x 7-tier matrix showed the reference tier
// resolving `Sha256Digest` on seven surfaces while Go, Rust and Zig refused it
// on `.runar.rs` — `compilers/go/frontend/parser_rustmacro.go`,
// `compilers/rust/src/frontend/parser_rustmacro.rs` and
// `compilers/zig/src/passes/parse_rust.zig` were the three type tables in the
// repo that had no arm for the name, out of the sixty-three (surface, tier)
// pairs. Java and Python and Ruby already had it.
//
// Zig's refusal was the loudest: it has no validator arm for an unknown
// property type at all, so the unresolved name survived validation and blew up
// in stack lowering as `UnsupportedOperation` — an internal error where the
// other tiers print "unsupported type 'Sha256Digest' in property declaration".
use runar::prelude::*;

#[runar::contract]
struct Sha256DigestAliasRust {
    current_hash: Sha256Digest,
}

impl Sha256DigestAliasRust {
    pub fn update(&mut self, new_hash: Sha256Digest) {
        self.current_hash = new_hash;
        assert!(true);
    }
}
