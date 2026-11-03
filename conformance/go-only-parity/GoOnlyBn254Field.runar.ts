// F-196 — the five raw BN254 scalar-field builtins. Their operands are unlock
// arguments, and every tier used to feed them straight into OP_ADD / OP_MUL
// and a bare OP_MOD: bn254FieldAdd(-1, 0) returned -1. Each entry point now
// aborts unless every operand is in [0, p-1]. The parity leg pins the bytes
// to Go; the execution leg in go-only-parity.test.ts runs each tier's script
// on @bsv/sdk's Spend.
import {
  SmartContract, assert,
  bn254FieldAdd, bn254FieldSub, bn254FieldMul, bn254FieldInv, bn254FieldNeg,
} from 'runar-lang';

export class GoOnlyBn254Field extends SmartContract {
  constructor() { super(); }
  public checkAdd(a: bigint, b: bigint, expected: bigint) {
    assert(bn254FieldAdd(a, b) === expected);
  }
  public checkSub(a: bigint, b: bigint, expected: bigint) {
    assert(bn254FieldSub(a, b) === expected);
  }
  public checkMul(a: bigint, b: bigint, expected: bigint) {
    assert(bn254FieldMul(a, b) === expected);
  }
  public checkInv(a: bigint, expected: bigint) {
    assert(bn254FieldInv(a) === expected);
  }
  public checkNeg(a: bigint, expected: bigint) {
    assert(bn254FieldNeg(a) === expected);
  }
}
