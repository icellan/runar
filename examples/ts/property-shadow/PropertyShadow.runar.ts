import { StatefulSmartContract, assert } from 'runar-lang';

/**
 * PropertyShadow — N-016 conformance fixture.
 *
 * Each property is read (and `count` written) AFTER a local of the same name
 * is declared. `this.target` / `this.count` must still mean the PROPERTY
 * (user decision R8: correct scoping). Before N-016 every tier resolved the
 * property read to the same-named local's stack slot, so
 * `assert(target == this.target)` compiled to OP_DUP OP_NUMEQUAL — always
 * true — and `this.count + count` doubled the local instead of reading state.
 */
class PropertyShadow extends StatefulSmartContract {
  readonly target: bigint;
  count: bigint;

  constructor(target: bigint, count: bigint) {
    super(target, count);
    this.target = target;
    this.count = count;
  }

  public bump(n: bigint) {
    const target = n + 1n;
    assert(target == this.target);
    const count = n;
    this.count = this.count + count;
    assert(this.count > count);
  }
}
