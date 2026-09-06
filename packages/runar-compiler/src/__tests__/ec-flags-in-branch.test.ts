/**
 * EC size flags must survive an `if`/`else` arm.
 *
 * `lowerIf` builds a fresh `LoweringContext` per arm to lower that arm's
 * bindings in isolation. Those two constructions omitted the `opts` argument,
 * so `ecCodegenOptions()` returned `undefined` inside every arm and the EC
 * emitters silently took their default, unoptimized path.
 *
 * That is not a missed optimization, it is a cross-tier divergence: Java
 * (`StackLower.java:924`) and Zig (`stack_lower.zig`) DO copy the options into
 * their arm contexts, so for the same source with the same flags those two
 * tiers emitted a script tens of kilobytes smaller than the other five — a
 * different locking script, therefore a different funding address.
 *
 * It also aims the whole feature away from its target. Branch-guarded crypto
 * (`if (usePQ) { verifySLHDSA(...) } else { verifyECDSA_P256(...) }`) is the
 * normal shape for a contract that needs the bytes back; a top-level EC call
 * with no conditional is the shape that needs them least.
 *
 * The scheduler is deliberately NOT inherited: `lowerIf` reconciles arms by
 * main-stack depth alone, so an arm must not spill to the alt stack. That was
 * already true by accident (the `schedulingByLiveness` getter checks
 * `_insideBranch`), but `shouldSwapOperands` does not, so the arm contexts pin
 * `schedulerMode: 'current'` explicitly rather than relying on it.
 */

import { describe, it, expect } from 'vitest';
import { compile, type CompileOptions } from '../index.js';

/** Same two `ecAdd` calls, once at top level and once inside if/else arms. */
const TOP_LEVEL = `
import { SmartContract, assert, ecAdd, type Point } from 'runar-lang';

class TopLevel extends SmartContract {
  readonly want: Point;
  constructor(want: Point) {
    super(want);
    this.want = want;
  }
  public unlock(p: Point, q: Point): void {
    const s: Point = ecAdd(p, q);
    const t: Point = ecAdd(s, q);
    assert(t === this.want);
  }
}
`;

const IN_BRANCH = `
import { SmartContract, assert, ecAdd, type Point } from 'runar-lang';

class InBranch extends SmartContract {
  readonly want: Point;
  constructor(want: Point) {
    super(want);
    this.want = want;
  }
  public unlock(p: Point, q: Point, flag: bigint): void {
    let t: Point = p;
    if (flag === 1n) {
      t = ecAdd(p, q);
    } else {
      t = ecAdd(q, p);
    }
    assert(t === this.want);
  }
}
`;

function bytes(source: string, options: CompileOptions): number {
  const r = compile(source, { fileName: 'C.runar.ts', ...options });
  if (!r.success || !r.artifact) {
    throw new Error(`compile failed: ${r.diagnostics.map(d => d.message).join('; ')}`);
  }
  return r.artifact.script.length / 2;
}

const ALL_ON: CompileOptions = {
  ecConstantPool: true,
  ecReductionSinking: true,
  ecFixedBaseComb: true,
};

describe('EC size flags inside if/else arms', () => {
  it('shrinks a top-level ecAdd (control: the flags work at all)', () => {
    const off = bytes(TOP_LEVEL, {});
    const on = bytes(TOP_LEVEL, ALL_ON);
    expect(on).toBeLessThan(off);
  });

  it('shrinks an ecAdd inside an if/else arm by the same proportion', () => {
    const off = bytes(IN_BRANCH, {});
    const on = bytes(IN_BRANCH, ALL_ON);

    expect(on).toBeLessThan(off);

    // The branch version must get essentially the same relative win as the
    // top-level one. Before the fix it got 0.0 %: `on` and `off` differed by
    // 19 bytes out of 48,800, entirely from the branch scaffolding.
    const topLevelRatio = bytes(TOP_LEVEL, ALL_ON) / bytes(TOP_LEVEL, {});
    const branchRatio = on / off;
    expect(branchRatio).toBeLessThan(topLevelRatio + 0.05);
  });

  it('leaves branch output byte-identical with every flag off', () => {
    // The guard that matters for the goldens: propagating options must not
    // move the default path.
    expect(bytes(IN_BRANCH, {})).toBe(bytes(IN_BRANCH, {
      ecConstantPool: false, ecReductionSinking: false, ecFixedBaseComb: false,
    }));
  });
});
