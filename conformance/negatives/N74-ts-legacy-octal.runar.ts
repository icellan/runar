// F-026: `012` is a legacy octal literal, a syntax error in strict-mode code
// (TypeScript modules are strict: TS1121 "Octal literals are not allowed").
// Pre-fix the tiers read it as 12 (ts, zig, java), 10 (go, ruby) or 0
// (python), and rust refused it. Every tier must refuse:
//   invalid TypeScript integer literal '012'
import { SmartContract, assert } from 'runar-lang';

class T extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(a: bigint): void {
    assert(a > 012);
  }
}
