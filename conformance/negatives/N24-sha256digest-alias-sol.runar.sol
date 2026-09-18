// N-108 — `Sha256Digest` is NOT a type name on the Solidity-like surface.
//
// `Sha256Digest` is a TypeScript-level alias: `packages/runar-lang/src/types.ts`
// declares `export type Sha256Digest = Sha256`. Each tier normalises it in the
// frontends whose surface language actually spells it — `.runar.ts`, `.runar.go`,
// `.runar.rs`, `.runar.py`, `.runar.zig`, `.runar.rb`, `.runar.java` — and the
// reference tier does NOT normalise it on `.runar.sol` or `.runar.move`:
// `TYPE_ALIASES` lives in `packages/runar-compiler/src/passes/01-parse.ts`, and
// neither `01-parse-sol.ts` nor `01-parse-move.ts` applies it. `docs/formats/`
// documents the alias for the Java surface only.
//
// Zig alone accepted it here (`compilers/zig/src/passes/parse_sol.zig` mapped
// the name), so a contract using it compiled in exactly one tier and was
// refused by the other six — a one-tier acceptance, which is the worst kind:
// it emits a locking script no peer will reproduce.
//
// The CONTROL for this fixture is the same source with the canonical `Sha256`
// spelling, which every tier accepts; it lives beside the positive corpus in
// `conformance/subtype-parity/`. Without that control a "rejection" here would
// be indistinguishable from a syntax error.
pragma runar ^0.1.0;

contract AliasOnSol is StatefulSmartContract {
    Sha256Digest currentHash;

    constructor(Sha256Digest _currentHash) {
        currentHash = _currentHash;
    }

    function update(Sha256Digest newHash) public {
        currentHash = newHash;
        require(true);
    }
}
