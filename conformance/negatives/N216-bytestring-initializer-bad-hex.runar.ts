import { SmartContract, assert } from 'runar-lang';
export class N216 extends SmartContract {
  readonly k: ByteString = "zzz" as ByteString;
  constructor() { super(); }
  public unlock() { assert(this.k === this.k); }
}
