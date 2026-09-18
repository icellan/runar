# Audit bug-ID collisions

Short index of audit identifiers that name more than one thing. Grep-first: if
you searched the repo for an ID and got two unrelated sets of hits, this is why.

## BUG-011 — two unrelated fixes (R-249)

`BUG-011` was used for two different defects, in every tier. 65 references
across 32 files, all of them correct about their own subject and none of them
saying which BUG-011 they mean.

### BUG-011 (a) — Rabin digest-encoding normalisation

The final comparison in `verifyRabinSig` must be NUMERIC, not byte-wise, and
the raw 32-byte digest push needs a non-negative sign byte before the compare.
Fixing it changed the Rabin sequence's last opcode from `OP_EQUAL` to
`OP_NUMEQUAL` and added four encoding-normalisation ops, taking the sequence to
18 opcodes (with BUG-010's padding-range check).

Lives in each tier's Rabin codegen:

    packages/runar-compiler/src/passes/rabin-codegen.ts
    compilers/{go/codegen/rabin.go, rust/src/codegen/rabin.rs,
               python/runar_compiler/codegen/rabin.py,
               ruby/lib/runar_compiler/codegen/rabin.rb,
               zig/src/passes/helpers/rabin_emitter.zig,
               java/src/main/java/runar/compiler/codegen/Rabin.java}

`conformance/witnesses/oracle-price.json` exists because of this one: the
fixture pinning `verifyRabinSig` had no witness, which is how the defect reached
RC.

### BUG-011 (b) — SLH-DSA exact signature-length guard

`verifySLHDSA_*` accepted a signature with trailing bytes: `sig || junk`
verified identically to `sig`. The fix enforces the exact length on-chain.

Lives in each tier's SLH-DSA codegen:

    packages/runar-compiler/src/passes/slh-dsa-codegen.ts
    packages/runar-testing/src/crypto/slh-dsa.ts
    compilers/{go/codegen/slh_dsa.go, rust/src/codegen/slh_dsa.rs,
               python/runar_compiler/codegen/slh_dsa.py,
               ruby/lib/runar_compiler/codegen/slh_dsa.rb,
               zig/src/passes/helpers/pq_emitters.zig,
               java/src/main/java/runar/compiler/codegen/SlhDsa.java}

### Why the references were not renamed

The IDs are historical: they appear in commit messages, in audit reports outside
this repository, and in `runar-verification/`, which this work does not touch.
Rewriting 65 comments would break the link between the code and the audit trail
that named them — the opposite of what the finding asks for. Recording the
collision once, where a search lands, keeps both.

Telling them apart in practice takes one look at the file name: a `rabin*`
module means (a), an `slh_dsa*` / `pq_emitters` module means (b).
