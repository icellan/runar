import { describe, it, expect, beforeAll } from 'vitest';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runStatefulSpend } from '../../packages/runar-testing/src/oracle/real-crypto-execution.js';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-362 — a private helper that emits an output is inlined into its caller at
 * ANF level, and its parameters were bound as ALIASES of the caller's argument
 * refs. A write to such a parameter (`a = a + 1n`) emitted a binding that no
 * later read used (every read of `a` resolved through the alias first), so the
 * helper committed the caller's ORIGINAL argument. Worse, the write landed on
 * whatever the bare name meant in the caller: a caller local or parameter of
 * the same name was silently overwritten.
 *
 * Fix (all 7 tiers): a helper parameter the helper body reassigns is bound as
 * a local of the inlined scope (`let a = <arg>`, spec §6.3 substitution)
 * instead of an alias, so later reads in the helper — straight-line, across
 * if/else arms, in loops, through nested helpers — see the write, and the
 * caller's variables are never touched.
 *
 * Oracle: `@bsv/sdk` Spend under consensus rules, via `runStatefulSpend` (the
 * SDK builds the call with its own ANF interpreter's auto-state; an attacker
 * build commits a chosen state with the interpreter bypassed).
 *
 * What this proves: for every shape below, the TS reference (fold ON, the
 * bytes `runStatefulSpend` deploys) continues with the hand-computed state,
 * and the script itself rejects the stale state the pre-fix bytes committed;
 * every other available tier emits the TS bytes in both fold modes; a helper
 * that does not reassign its parameter keeps its pre-fix bytes.
 * What it does NOT prove: execution of the fold-OFF bytes (they equal the
 * fold-ON bytes for every shape here, which the test asserts); the six other
 * SDK interpreters' auto-state (covered by the conformance/anf-interpreter
 * n362-* cases); any shape not listed below.
 */

const stateful = (name: string, members: string, prop = 'count: bigint') => {
  const [p, t] = prop.split(': ');
  return `import { StatefulSmartContract, assert, cat } from 'runar-lang';
import type { ByteString } from 'runar-lang';
class ${name} extends StatefulSmartContract {
  ${prop};
  constructor(${p}: ${t}) { super(${p}); this.${p} = ${p}; }
${members}
}
`;
};

interface Run {
  args: unknown[];
  /** The state the honest spend must continue with. */
  right: Record<string, unknown>;
  /** A state the script must reject (what the pre-fix bytes committed). */
  stale: Record<string, unknown>;
}
interface Shape {
  name: string;
  src: string;
  ctor: (bigint | string)[];
  runs: Run[];
  /** Attacker builds whose args make a caller-side assert fail: the script must reject. */
  rejects?: { args: unknown[]; state: Record<string, unknown> }[];
}

const SHAPES: Shape[] = [
  {
    name: 'InlStraight',
    src: stateful('InlStraight', `  private emit(a: bigint): void { a = a + 1n; this.addOutput(1000n, a); }
  public m(x: bigint) { this.emit(x); }`),
    ctor: [0n],
    runs: [{ args: [5n], right: { count: 6n }, stale: { count: 5n } }],
  },
  {
    name: 'InlBoth',
    src: stateful('InlBoth', `  private emit(a: bigint, c: boolean): void {
    if (c) { a = a + 1n; } else { a = a + 2n; }
    this.addOutput(1000n, a);
  }
  public m(x: bigint, c: boolean) { this.emit(x, c); }`),
    ctor: [0n],
    runs: [
      { args: [5n, true], right: { count: 6n }, stale: { count: 5n } },
      { args: [5n, false], right: { count: 7n }, stale: { count: 5n } },
    ],
  },
  {
    name: 'InlOneArm',
    src: stateful('InlOneArm', `  private emit(a: bigint, c: boolean): void {
    if (c) { a = a + 1n; }
    this.addOutput(1000n, a);
  }
  public m(x: bigint, c: boolean) { this.emit(x, c); }`),
    ctor: [0n],
    runs: [
      { args: [5n, true], right: { count: 6n }, stale: { count: 5n } },
      { args: [5n, false], right: { count: 5n }, stale: { count: 6n } },
    ],
  },
  {
    name: 'InlLoop',
    src: stateful('InlLoop', `  private emit(a: bigint): void {
    for (let i = 0n; i < 3n; i++) { a = a + i; }
    this.addOutput(1000n, a);
  }
  public m(x: bigint) { this.emit(x); }`),
    ctor: [0n],
    runs: [{ args: [5n], right: { count: 8n }, stale: { count: 5n } }],
  },
  {
    // A helper param named like the property: bound as `count@local`.
    name: 'InlPropNamed',
    src: stateful('InlPropNamed', `  private emit(count: bigint): void {
    count = count + 1n;
    this.addOutput(1000n, count + this.count);
  }
  public m(x: bigint) { this.emit(x); }`),
    ctor: [10n],
    runs: [{ args: [5n], right: { count: 16n }, stale: { count: 15n } }],
  },
  {
    // A reassigning helper passing its reassigned param to another one.
    name: 'InlNested',
    src: stateful('InlNested', `  private inner(b: bigint): void { b = b * 2n; this.addOutput(1000n, b); }
  private emit(a: bigint): void { a = a + 1n; this.inner(a); }
  public m(x: bigint) { this.emit(x); }`),
    ctor: [0n],
    runs: [{ args: [5n], right: { count: 12n }, stale: { count: 10n } }],
  },
  {
    // The caller's local `a` must survive the helper's write to ITS `a`.
    name: 'InlCallerLocal',
    src: stateful('InlCallerLocal', `  private emit(a: bigint): void { a = a + 1n; this.addOutput(1000n, a); }
  public m(x: bigint, e: bigint) {
    const a: bigint = x * 2n;
    this.emit(x);
    assert(x + a === e);
  }`),
    ctor: [0n],
    runs: [{ args: [5n, 15n], right: { count: 6n }, stale: { count: 5n } }],
    // Pre-fix the helper overwrote the caller's `a` with 6: x + a === 11.
    rejects: [{ args: [5n, 11n], state: { count: 6n } }],
  },
  {
    // The caller's own parameter, passed under the same name, must not change.
    name: 'InlCallerParam',
    src: stateful('InlCallerParam', `  private emit(a: bigint): void { a = a + 1n; this.addOutput(1000n, a); }
  public m(a: bigint, e: bigint) { this.emit(a); assert(a === e); }`),
    ctor: [0n],
    runs: [{ args: [5n, 5n], right: { count: 6n }, stale: { count: 5n } }],
    rejects: [{ args: [5n, 6n], state: { count: 6n } }],
  },
  {
    // A ByteString param reassigned and then compared: the equality must stay
    // a byte comparison (5-byte operands abort a numeric one).
    name: 'InlBytes',
    src: stateful('InlBytes', `  private emit(a: ByteString, b: ByteString): void {
    a = cat(a, a);
    assert(a === b);
    this.addOutput(1000n, a);
  }
  public m(x: ByteString, y: ByteString) { this.emit(x, y); }`, 'data: ByteString'),
    ctor: ['00'],
    runs: [
      {
        args: ['0102030405', '01020304050102030405'],
        right: { data: '01020304050102030405' },
        stale: { data: '0102030405' },
      },
    ],
  },
];

/** An inlined helper that does NOT reassign: its pre-fix TS bytes must not move. */
const NO_REASSIGN = stateful('InlNoReassign', `  private emit(a: ByteString, b: ByteString): void { assert(a === b); this.addOutput(1000n, a); }
  public m(x: ByteString, y: ByteString) { this.emit(x, y); }`, 'data: ByteString');
const NO_REASSIGN_HEAD_SHA16 = 'a0c55ba22b27dfda';

const sha16 = (hex: string) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex').slice(0, 16);
const foldOff = (t: Tier): Tier => ({ ...t, argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'] });
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TS_TIER = TIERS.find((t) => t.id === 'ts');
const MODES: { label: string; tier: (t: Tier) => Tier }[] = [
  { label: 'fold OFF', tier: foldOff },
  { label: 'fold ON', tier: (t) => t },
];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n362-inl-param-'));
});
function write(name: string, src: string): string {
  const p = join(dir, name);
  writeFileSync(p, src);
  return p;
}

const spend = (s: Shape, args: unknown[], attackerNewState?: Record<string, unknown>) =>
  runStatefulSpend({
    source: s.src,
    fileName: `${s.name}.runar.ts`,
    method: 'm',
    args: [...args],
    constructorArgs: s.ctor,
    signerKey: 'alice',
    satoshis: 1000,
    ...(attackerNewState ? { attackerNewState } : {}),
  });

describe('N-362 an inlined output-emitting helper that reassigns its own param — seven tiers, executed on @bsv/sdk', () => {
  it('the TS reference and at least one other tier are available (all seven in CI)', () => {
    expect(TS_TIER).toBeDefined();
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const s of SHAPES) {
    describe(s.name, () => {
      for (const r of s.runs) {
        const label = JSON.stringify(r.args, (_k, v) => (typeof v === 'bigint' ? `${v}` : v));
        it(`m(${label}) continues with the right state`, async () => {
          const res = await spend(s, r.args);
          expect(res.vmError ?? '', 'honest spend rejected').toBe('');
          expect(res.vmAccepted).toBe(true);
          expect(res.continuationState).toEqual(r.right);
        }, 120_000);

        it(`m(${label}) — the script rejects the stale state`, async () => {
          const res = await spend(s, r.args, r.stale);
          expect(res.reachedEngine, 'rejection did not come from the script').toBe(true);
          expect(res.vmAccepted, 'stale state accepted').toBe(false);
        }, 120_000);
      }

      for (const rej of s.rejects ?? []) {
        it('the script still checks the caller\'s own variable', async () => {
          const res = await spend(s, rej.args, rej.state);
          expect(res.reachedEngine, 'rejection did not come from the script').toBe(true);
          expect(res.vmAccepted, 'caller variable was overwritten by the helper').toBe(false);
        }, 120_000);
      }

      let tsHex: Record<string, string> = {};
      beforeAll(() => {
        tsHex = Object.fromEntries(
          MODES.map((m) => [m.label, compileHex(m.tier(TS_TIER!), write(`${s.name}.runar.ts`, s.src))]),
        );
      }, 240_000);

      it('the executed fold-ON bytes are also the fold-OFF bytes', () => {
        expect(tsHex['fold OFF']).toBe(tsHex['fold ON']);
      });

      for (const mode of MODES) {
        for (const tier of TIERS.filter((t) => t.id !== 'ts')) {
          it(`${tier.id} emits the TS reference bytes (${mode.label})`, () => {
            expect(compileHex(mode.tier(tier), write(`${s.name}.runar.ts`, s.src))).toBe(tsHex[mode.label]);
          }, 240_000);
        }
      }
    });
  }

  describe('a helper that does not reassign its param is byte-neutral', () => {
    for (const mode of MODES) {
      it(`TS still emits its pre-fix bytes (${mode.label})`, () => {
        expect(sha16(compileHex(mode.tier(TS_TIER!), write('InlNoReassign.runar.ts', NO_REASSIGN)))).toBe(
          NO_REASSIGN_HEAD_SHA16,
        );
      }, 240_000);
    }
  });
});
