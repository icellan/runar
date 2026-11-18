// D18 - issue #180's Lock: a public stateful method that writes state and
// calls addRawOutput() but never addOutput(). Any declared output replaces the
// auto-injected continuation and a raw output never carries state, so the
// write to n would be dropped and the contract's value would go to the
// spender's change. Every tier refuses:
//  method 'lock' writes contract state on a path that reaches no addOutput():
//  a method that declares its own outputs (addOutput/addRawOutput) gets no
//  auto-injected continuation, so on that path the state write would be lost
//  and the contract's satoshis would leave with the spend. Add
//  this.addOutput(satoshis, ...) on every path that writes state, or stop
//  writing state on a path meant to end the contract
import { StatefulSmartContract, cat, toByteString } from 'runar-lang';
import type { Point } from 'runar-lang';

class N536 extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }

  public lock(p: Point) {
    this.addRawOutput(1000n, cat(cat(toByteString('40'), p), toByteString('87')));
    this.n = this.n + 1n;
  }
}
