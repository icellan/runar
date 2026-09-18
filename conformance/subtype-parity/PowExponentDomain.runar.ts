// R-169, the `pow` half — the cross-tier gate on `pow`'s enforced exponent
// domain, in the one place that compiles with CONSTANT FOLDING ON.
//
// `pow` unrolls 32 conditional multiplies, so it computes `base^min(exp, 32)`.
// Until R-169 nothing guarded the exponent: `pow(2, 40)` ran to completion on
// the real VM and returned 2^32. Every tier's constant folder, meanwhile,
// computed the TRUE power for any `0 <= exp <= 256`. So for exactly
// `33 <= exp <= 256` the same source compiled fold-ON and fold-OFF produced
// scripts accepting MUTUALLY EXCLUSIVE inputs, in all seven tiers at once —
// cross-tier hex parity was green on the wrong answer.
//
// The fix puts one number in three places per tier: the unroll count, the
// script guard `OP_DUP <0> <33> OP_WITHIN OP_VERIFY`, and the folder's
// decline-outside bound. WHY THIS FIXTURE EXISTS is the third of those. The
// conformance golden suite runs `--disable-constant-folding`, so a tier whose
// folder still carried the old 256 bound would emit identical goldens and be
// invisible there. This corpus compiles with folding ON (no fold flag is
// passed — see subtype-parity.test.ts), so:
//
//   - `outOfDomain` below is an all-constant `pow` with an exponent in the old
//     33..256 window. A tier that still folds it emits a single literal push
//     where the others emit the 32-round guarded fragment, and the hex
//     diverges on the spot.
//   - `inDomain` is an all-constant `pow` INSIDE the bound: every tier must
//     fold it, and to the same value. A tier that declined too early diverges
//     the other way, so the gate has teeth in both directions.
//   - `runtimeExp` keeps the guard itself in the compared bytes with a
//     non-constant exponent, which is the only shape a folder cannot reach.
//
// The behaviour of the emitted script — that it ABORTS outside the domain
// rather than returning `base^32` — is executed on the real interpreter by
// `packages/runar-compiler/src/__tests__/r169-pow-exponent-domain.test.ts` and
// by the `exponentiate` rows in `conformance/witnesses/real-crypto/math-demo.json`.
// This file gates the seven tiers agreeing about it.
import { SmartContract, assert, pow } from 'runar-lang';

export class PowExponentDomain extends SmartContract {
  readonly tag: bigint;

  constructor(tag: bigint) {
    super(tag);
    this.tag = tag;
  }

  public unlock(base: bigint, exp: bigint) {
    // Constant, inside the enforced domain: every tier folds this to 2^32.
    const inDomain: bigint = pow(2n, 32n);
    // Constant, inside the OLD 33..256 fold window and OUTSIDE the domain the
    // script computes: no tier may fold this. The emitted guard makes the
    // method unspendable, which is the point — the wrong answer used to be
    // spendable.
    const outOfDomain: bigint = pow(2n, 40n);
    // Non-constant exponent: the guard bytes themselves, unreachable by any
    // folder.
    const runtimeExp: bigint = pow(base, exp);

    assert(inDomain === 4294967296n);
    assert(outOfDomain === this.tag);
    assert(runtimeExp >= 0n);
  }
}
