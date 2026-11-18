// D18 - the raw output sits in an inlined private helper and the state write
// in the public method; the effects follow the helper, so every tier refuses:
//  method 'pay' writes contract state on a path that reaches no addOutput():
//  a method that declares its own outputs (addOutput/addRawOutput) gets no
//  auto-injected continuation, so on that path the state write would be lost
//  and the contract's satoshis would leave with the spend. Add
//  this.addOutput(satoshis, ...) on every path that writes state, or stop
//  writing state on a path meant to end the contract
import { StatefulSmartContract, ByteString } from 'runar-lang';

class N537 extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }

  public pay(script: ByteString) {
    this.count = this.count + 1n;
    this.emit(script);
  }

  private emit(script: ByteString): void {
    this.addRawOutput(1000n, script);
  }
}
