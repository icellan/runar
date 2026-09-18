// Positive control for the rejection-parity gate.
//
// Every tier in the matrix must ACCEPT this contract. Without it, a tier whose
// invocation is malformed (wrong argv, missing jar, a command string with a
// space in it) fails on every input and scores a perfect 13/13 "rejects
// everything" — which is exactly how the Ruby and Java rows in this suite were
// passing before R-100. This file is deliberately NOT named `N**` so the
// negative-corpus glob does not pick it up.
import { SmartContract, assert } from 'runar-lang';

export class PositiveControl extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public go(x: bigint) {
    assert(x > this.a);
  }
}
