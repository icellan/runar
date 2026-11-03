import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, type Tier } from './tier-harness.js';

/**
 * N-097 (subsumes N-195): seven-tier parity for the gate that decides whether
 * dead-binding elimination runs after the EC optimizer.
 *
 * The TS reference (`optimizer/anf-ec.ts` `optimizeEC`) runs DCE over EVERY
 * method of the program iff at least one EC rewrite rule fired in at least
 * one method; when no rule fires anywhere, the program is returned untouched,
 * dead bindings included. The tiers used three different gates:
 *
 *   go                       DCE only the methods in which a rule fired
 *   python / ruby / zig      DCE every method iff some method has a top-level
 *                            EC intrinsic CALL (fired or not)
 *   java                     same, but the call may be nested in if/loop
 *   rust                     the TS gate
 *
 * A dead pure binding (`const dead = 7n`) is emitted as a push + drop/nip when
 * kept, so the gate is directly visible in the locking-script bytes. The four
 * shapes isolate one gate each:
 *
 *   A  a rule fires in method a(); method b() carries the dead binding
 *      (Go kept it, the others removed it)
 *   B  one method, a non-rule EC predicate (ecOnCurve) + a dead binding
 *      (python/ruby/zig/java removed it; TS keeps it: no rule fired)
 *   C  as B but the EC call sits inside an if, the dead binding at top level
 *      (java removed it)
 *   D  no EC at all + a dead binding (control: every tier keeps it)
 *
 * The pinned digests are the TS reference tier's output at the time of the
 * fix; every tier must reproduce them in both fold modes.
 *
 * What this proves: every available tier's one-shot source->hex CLI emits the
 * TS reference's bytes for the four gate shapes, fold-ON and fold-OFF, so a
 * tier whose DCE gate differs from "some rule fired anywhere" fails here.
 * What it does NOT prove: that the TS gate is the RIGHT policy (DCE running on
 * every program is N-140/R-194's separate question), the non-TS surfaces (the
 * gate lives after every parser has produced the same ANF), or that the
 * emitted scripts execute — the shapes differ only in whether a pure,
 * unreferenced constant is pushed and dropped.
 */

const HEADER = (imports: string) =>
  `import { SmartContract, assert, Addr, PubKey, hash160, ${imports} } from 'runar-lang';\n`;

const SHAPES: Record<string, { source: string; sha256: string; len: number }> = {
  A: {
    source: `${HEADER('ecMulGen, ecOnCurve')}import type { Point } from 'runar-lang';

class N097ShapeA extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public a() {
    const g: Point = ecMulGen(1n);
    assert(ecOnCurve(g));
  }

  public b(pubKey: PubKey) {
    const dead: bigint = 7n;
    assert(hash160(pubKey) === this.pubKeyHash);
  }
}
`,
    sha256: '2e85bb210e46dd834b563af00887b25ab3ece4ed1202607abf6583a1af5b43fa',
    len: 1766,
  },
  B: {
    source: `${HEADER('ecOnCurve')}import type { Point } from 'runar-lang';

class N097ShapeB extends SmartContract {
  readonly pubKeyHash: Addr;
  readonly pt: Point;

  constructor(pubKeyHash: Addr, pt: Point) {
    super(pubKeyHash, pt);
    this.pubKeyHash = pubKeyHash;
    this.pt = pt;
  }

  public unlock(pubKey: PubKey) {
    const dead: bigint = 7n;
    assert(ecOnCurve(this.pt));
    assert(hash160(pubKey) === this.pubKeyHash);
  }
}
`,
    sha256: 'f1b0fc00c2af6e2c8c3d05125c06c4d45eed33044cbb7d2ae62ba33651ac5b05',
    len: 1628,
  },
  C: {
    source: `${HEADER('ecOnCurve')}import type { Point } from 'runar-lang';

class N097ShapeC extends SmartContract {
  readonly pubKeyHash: Addr;
  readonly pt: Point;

  constructor(pubKeyHash: Addr, pt: Point) {
    super(pubKeyHash, pt);
    this.pubKeyHash = pubKeyHash;
    this.pt = pt;
  }

  public unlock(pubKey: PubKey, check: boolean) {
    const dead: bigint = 7n;
    if (check) {
      assert(ecOnCurve(this.pt));
    }
    assert(hash160(pubKey) === this.pubKeyHash);
  }
}
`,
    sha256: '834e44bb589266e370adcc43c8df0d7b961bdc9eb98c0e6d7c2d4d324e865b2b',
    len: 1652,
  },
  D: {
    source: `import { SmartContract, assert, Addr, PubKey, hash160 } from 'runar-lang';

class N097ShapeD extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(pubKey: PubKey) {
    const dead: bigint = 7n;
    assert(hash160(pubKey) === this.pubKeyHash);
  }
}
`,
    sha256: '276868d37b2fa493492958df115029dc8d228208093f66e3b2716248585a9472',
    len: 12,
  },
};

const DIR = mkdtempSync(join(tmpdir(), 'n097-ec-dce-gate-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);

/** The same tier with `--disable-constant-folding` appended (every CLI accepts it). */
function foldOff(t: Tier): Tier {
  return { ...t, argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'] };
}

const sha = (hex: string) => createHash('sha256').update(hex).digest('hex');

describe('N-097: the post-EC-optimizer DCE gate is the TS reference gate in every tier', () => {
  it('the TS reference tier and at least one peer are available (else the comparison is vacuous)', () => {
    expect(tiers.find((t) => t.id === 'ts')).toBeDefined();
    expect(tiers.length).toBeGreaterThanOrEqual(2);
  });

  for (const [shape, { source, sha256, len }] of Object.entries(SHAPES)) {
    const file = join(DIR, `N097Shape${shape}.runar.ts`);
    writeFileSync(file, source);
    for (const tier of tiers) {
      for (const [mode, t] of [['fold-on', tier], ['fold-off', foldOff(tier)]] as const) {
        it(`${tier.id} ${mode}: shape ${shape} emits the TS reference bytes`, () => {
          const hex = compileHex(t, file);
          expect({ len: hex.length, sha256: sha(hex) }).toEqual({ len, sha256 });
        }, tier.timeoutMs);
      }
    }
  }
});
