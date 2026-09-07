/**
 * Liveness scheduler + EC constant pool — semantic equivalence, source vs script.
 *
 * Both experiments move values around the stack (the scheduler parks results
 * on the alt stack; the pool serves a constant from a resident slot). That is
 * exactly the class of change that can produce a script which still runs and
 * still leaves a truthy top-of-stack while computing something else, so a byte
 * count proves nothing on its own.
 *
 * `runDifferentialExecution` compiles a contract, executes the deployed script
 * on the real @bsv/sdk engine, AND runs the same spend through the ANF
 * interpreter — a source-semantics oracle that knows nothing about stack
 * layout. Running it once per variant on the same witness gives translation
 * validation:
 *
 *   current(w) == variant(w) == interpreter(w)   for every witness w
 *
 * The witnesses are NOT invented here: they come from `conformance/witnesses/`,
 * the same specs CI already runs, so every expectation is one the repo has
 * independently committed to. `conformance/witnesses/coverage-claims.test.ts`
 * enforces that each spec carries at least one accept AND one reject, so a
 * variant that made everything pass cannot slip through.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { runDifferentialExecution, type WitnessArg } from '../oracle/differential-execution.js';

const CONFORMANCE = resolve(__dirname, '../../../../conformance');
const WITNESS_DIR = join(CONFORMANCE, 'witnesses');
const TESTS_DIR = join(CONFORMANCE, 'tests');

/** Decode a method-argument literal: bigint ("27n"), boolean, or bytes ("0x…"). */
function decodeArg(v: unknown): WitnessArg {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') {
    if (/^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
    if (v.startsWith('0x')) return Uint8Array.from(Buffer.from(v.slice(2), 'hex'));
  }
  throw new Error(`unencodable witness arg: ${JSON.stringify(v)}`);
}

function decodeCtor(v: unknown): bigint | boolean | string {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') {
    if (/^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
    if (v.startsWith('0x')) return v.slice(2);
  }
  throw new Error(`unencodable constructor arg: ${JSON.stringify(v)}`);
}

interface Spend { method: string; args: unknown[]; expect: 'accept' | 'reject'; note?: string }
interface Spec { fixture: string; constructorArgs?: Record<string, unknown>; spends: Spend[] }

const NON_SPEC_JSON = new Set(['coverage-ledger.json']);
const SPECS: Spec[] = readdirSync(WITNESS_DIR)
  .filter(f => f.endsWith('.json') && !NON_SPEC_JSON.has(f))
  .sort()
  .map(f => JSON.parse(readFileSync(join(WITNESS_DIR, f), 'utf-8')) as Spec);

/** Variants under test. `current` is the baseline every other is compared to. */
const VARIANTS = [
  { name: 'liveness', opts: { schedulerMode: 'liveness' as const } },
  { name: 'ec-pool', opts: { ecConstantPool: true } },
  { name: 'both', opts: { schedulerMode: 'liveness' as const, ecConstantPool: true } },
  // Everything at once. Each optimization is proved separately elsewhere, but
  // they compose in one compilation and the combination is what a user would
  // actually turn on, so it gets its own pass over the witness corpus.
  {
    name: 'all',
    opts: {
      schedulerMode: 'liveness' as const,
      ecConstantPool: true,
      ecReductionSinking: true,
      ecFixedBaseComb: true,
    },
  },
];


// ---------------------------------------------------------------------------
// EC corpus.
//
// The witness corpus in `conformance/witnesses/` contains no EC builtin — it is
// arithmetic, bitwise, boolean, loops, if/else and shifts. So `ec-pool`, `both`
// and `all` compiled the SAME script as the baseline for all 10 specs and every
// assertion in this file was `x === x`: three of the four variants were proving
// nothing. A sign-lattice bug in fieldSub's cheap path — the
// `ecAdd((0,1), (2^256-1,1))` class this whole optimization exists to avoid —
// would have left the file green.
//
// These specs are declared here rather than added to `conformance/witnesses/`
// because that corpus feeds other consumers (the CI `witnesses/` step, the
// coverage ledger) with their own expectations about its contents. The EC
// variants need coverage in THIS oracle; they do not need to change what the
// shared corpus means.
//
// The points are the real secp256k1 generator and its small multiples, so the
// accept cases are arithmetic facts, not recorded outputs:
//   G + 2G = 3G, and every one of them is on the curve.
// `ecAdd(G, G)` is deliberately absent: the affine formula cannot double, which
// is a documented property of the emitter and not what this file tests.
// ---------------------------------------------------------------------------

const G = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
        + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
const TWO_G = 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
            + '1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a';
const THREE_G = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
              + '388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672';

const EC_SOURCE = `
import { SmartContract, assert, ecAdd, ecOnCurve, type Point } from 'runar-lang';

class EcSum extends SmartContract {
  readonly want: Point;
  constructor(want: Point) {
    super(want);
    this.want = want;
  }
  public unlock(a: Point, b: Point): void {
    assert(ecOnCurve(a));
    assert(ecOnCurve(b));
    const s: Point = ecAdd(a, b);
    assert(s === this.want);
  }
}
`;

const hexBytes = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

interface InlineSpec {
  name: string;
  source: string;
  fileName: string;
  constructorArgs: Record<string, bigint | boolean | string>;
  spends: Array<{ method: string; args: WitnessArg[]; expect: 'accept' | 'reject'; note: string }>;
}

const EC_SPECS: InlineSpec[] = [
  {
    name: 'ec-sum',
    source: EC_SOURCE,
    fileName: 'EcSum.runar.ts',
    constructorArgs: { want: THREE_G },
    spends: [
      {
        method: 'unlock', args: [hexBytes(G), hexBytes(TWO_G)], expect: 'accept',
        note: 'G + 2G = 3G, both operands on the curve',
      },
      {
        method: 'unlock', args: [hexBytes(TWO_G), hexBytes(G)], expect: 'accept',
        note: 'addition commutes; exercises the other operand order',
      },
      {
        method: 'unlock', args: [hexBytes(G), hexBytes(THREE_G)], expect: 'reject',
        note: 'G + 3G = 4G != 3G — near miss, still two on-curve points',
      },
    ],
  },
];

describe('experimental backends preserve acceptance', () => {
  it('found the witness corpus', () => {
    expect(SPECS.length).toBeGreaterThanOrEqual(10);
  });

  for (const spec of SPECS) {
    const fixtureDir = join(TESTS_DIR, spec.fixture);
    const srcCfg = JSON.parse(readFileSync(join(fixtureDir, 'source.json'), 'utf-8')) as
      { sources?: Record<string, string>; path?: string };
    const tsRel = srcCfg.sources?.['.runar.ts'] ?? srcCfg.path;
    if (!tsRel) throw new Error(`no .runar.ts source in ${spec.fixture}/source.json`);
    const srcPath = resolve(fixtureDir, tsRel);
    const source = readFileSync(srcPath, 'utf-8');
    const fileName = srcPath.split('/').pop()!;
    const ctor: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(spec.constructorArgs ?? {})) ctor[k] = decodeCtor(v);

    describe(spec.fixture, () => {
      for (const s of spec.spends) {
        for (const variant of VARIANTS) {
          it(`${variant.name}: ${s.method}(${s.args.join(',')}) → ${s.expect}`, () => {
            const common = {
              source, fileName, method: s.method,
              args: s.args.map(decodeArg), constructorArgs: ctor,
            };
            const base = runDifferentialExecution(common);
            const other = runDifferentialExecution({ ...common, ...variant.opts });

            // The witness spec itself must hold, or the comparison is vacuous.
            expect(base.vmAccepted, 'witness spec disagrees with the shipping compiler')
              .toBe(s.expect === 'accept');
            // Translation validation, both directions against the interpreter.
            expect(other.vmAccepted).toBe(base.vmAccepted);
            expect(base.vmAccepted).toBe(base.interpreterAccepted);
            expect(other.vmAccepted).toBe(other.interpreterAccepted);
            expect(other.vmError ?? null).toBe(base.vmError ?? null);
          });
        }
      }
    });
  }

  for (const spec of EC_SPECS) {
    describe(spec.name, () => {
      for (const s of spec.spends) {
        for (const variant of VARIANTS) {
          it(`${variant.name}: ${s.method} → ${s.expect} (${s.note})`, () => {
            const common = {
              source: spec.source, fileName: spec.fileName, method: s.method,
              args: s.args, constructorArgs: spec.constructorArgs,
            };
            const base = runDifferentialExecution(common);
            const other = runDifferentialExecution({ ...common, ...variant.opts });

            expect(base.vmAccepted, 'EC spec disagrees with the shipping compiler')
              .toBe(s.expect === 'accept');
            expect(other.vmAccepted).toBe(base.vmAccepted);
            expect(base.vmAccepted).toBe(base.interpreterAccepted);
            expect(other.vmAccepted).toBe(other.interpreterAccepted);
            expect(other.vmError ?? null).toBe(base.vmError ?? null);
          });
        }
      }
    });
  }

  /**
   * Every variant must actually change bytes somewhere in the combined corpus.
   *
   * This guard used to cover `schedulerMode: 'liveness'` ONLY. The other three
   * variants all enable EC flags, the witness corpus has no EC builtin, and so
   * they compiled a byte-identical script for all 10 specs — every assertion
   * above was comparing a script against itself, and the file would have stayed
   * green through any EC codegen bug whatsoever.
   *
   * Checking each variant by name is the point: a variant that stops firing
   * fails HERE with its own name, instead of silently becoming decoration.
   */
  it('every variant changes bytes somewhere in the corpus', () => {
    const probes: Array<{ label: string; common: Parameters<typeof runDifferentialExecution>[0] }> = [];

    for (const spec of SPECS) {
      const fixtureDir = join(TESTS_DIR, spec.fixture);
      const srcCfg = JSON.parse(readFileSync(join(fixtureDir, 'source.json'), 'utf-8')) as
        { sources?: Record<string, string>; path?: string };
      const tsRel = srcCfg.sources?.['.runar.ts'] ?? srcCfg.path;
      if (!tsRel) continue;
      const srcPath = resolve(fixtureDir, tsRel);
      const ctor: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(spec.constructorArgs ?? {})) ctor[k] = decodeCtor(v);
      const first = spec.spends[0]!;
      probes.push({
        label: spec.fixture,
        common: {
          source: readFileSync(srcPath, 'utf-8'),
          fileName: srcPath.split('/').pop()!,
          method: first.method,
          args: first.args.map(decodeArg),
          constructorArgs: ctor as Record<string, bigint | boolean | string>,
        },
      });
    }
    for (const spec of EC_SPECS) {
      const first = spec.spends[0]!;
      probes.push({
        label: spec.name,
        common: {
          source: spec.source, fileName: spec.fileName,
          method: first.method, args: first.args,
          constructorArgs: spec.constructorArgs,
        },
      });
    }

    const report: string[] = [];
    for (const variant of VARIANTS) {
      const changed: string[] = [];
      for (const probe of probes) {
        const base = runDifferentialExecution(probe.common);
        const other = runDifferentialExecution({ ...probe.common, ...variant.opts });
        if (other.lockingHex !== base.lockingHex) {
          changed.push(probe.label);
          // And it must never be bigger — every optimization compares measured
          // bytes before choosing, so a growth is a cost-model defect.
          expect(other.lockingHex.length, `${variant.name} grew ${probe.label}`)
            .toBeLessThan(base.lockingHex.length);
        }
      }
      expect(changed.length, `variant "${variant.name}" was a no-op on the ENTIRE corpus — `
        + 'its assertions above compared a script against itself')
        .toBeGreaterThan(0);
      report.push(`  ${variant.name}: ${changed.join(', ')}`);
    }
    console.log(report.join('\n'));
  });
});
