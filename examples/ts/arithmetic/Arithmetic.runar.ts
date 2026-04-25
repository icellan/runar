import { SmartContract, assert } from 'runar-lang';

class Arithmetic extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(a: bigint, b: bigint): void {
    const sum: bigint = a + b;
    const diff: bigint = a - b;
    const prod: bigint = a * b;
    const quot: bigint = a / b;
    const result: bigint = sum + diff + prod + quot;
    assert(result === this.target);
  }
}
