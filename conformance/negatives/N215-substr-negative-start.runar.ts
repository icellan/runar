import { SmartContract, assert } from 'runar-lang';
export class N215 extends SmartContract {
  readonly a: ByteString;
  constructor(a: ByteString) { super(a); this.a = a; }
  public unlock() { assert(substr(this.a, -5n, 3n) === this.a); }
}
