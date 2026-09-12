// N-108 — `Sha256Digest` is NOT a type name on the Move-style surface either.
//
// The `.runar.move` half of N24. Same reference-tier rule, same one-tier
// outlier: `compilers/zig/src/passes/parse_move.zig` carried the alias in its
// type table while TypeScript, Go, Rust, Python, Ruby and Java all refuse the
// name at the validator ("unsupported type 'Sha256Digest' in property
// declaration").
//
// Recorded here rather than "fixed" by teaching the other six the alias,
// because the reference tier is the definition of the surface and it does not
// spell `Sha256Digest` on `.sol` / `.move`. Widening the surface vocabulary is
// a language change; converging Zig onto the reference is a parity fix.
module AliasOnMove {
    use runar::StatefulSmartContract;

    resource struct AliasOnMove {
        current_hash: &mut Sha256Digest,
    }

    public fun update(contract: &mut AliasOnMove, new_hash: Sha256Digest) {
        contract.current_hash = new_hash;
        assert!(true, 0);
    }
}
