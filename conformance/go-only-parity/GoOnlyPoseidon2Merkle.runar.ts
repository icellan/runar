// F-092 — merkleRootPoseidon2KB (Poseidon2 KoalaBear Merkle), depth 1. Go-only by project policy.
import { SmartContract, assert, merkleRootPoseidon2KB } from 'runar-lang';

export class GoOnlyPoseidon2Merkle extends SmartContract {
  constructor() { super(); }
  public verify(
    l0: bigint, l1: bigint, l2: bigint, l3: bigint, l4: bigint, l5: bigint, l6: bigint, l7: bigint,
    s0: bigint, s1: bigint, s2: bigint, s3: bigint, s4: bigint, s5: bigint, s6: bigint, s7: bigint,
    idx: bigint, expected: bigint,
  ) {
    assert(merkleRootPoseidon2KB(l0, l1, l2, l3, l4, l5, l6, l7, s0, s1, s2, s3, s4, s5, s6, s7, idx, 1n) === expected);
  }
}
