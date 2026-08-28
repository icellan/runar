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

  it('the liveness scheduler really does change bytes somewhere in this corpus', () => {
    // Guards against the whole suite passing because every variant compiled to
    // the identical script.
    const changed: string[] = [];
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
      const common = {
        source: readFileSync(srcPath, 'utf-8'),
        fileName: srcPath.split('/').pop()!,
        method: first.method,
        args: first.args.map(decodeArg),
        constructorArgs: ctor,
      };
      const base = runDifferentialExecution(common);
      const sched = runDifferentialExecution({ ...common, schedulerMode: 'liveness' });
      if (sched.lockingHex !== base.lockingHex) {
        changed.push(spec.fixture);
        // And it must never be bigger — the cost model picks per method.
        expect(sched.lockingHex.length, `${spec.fixture} grew`)
          .toBeLessThan(base.lockingHex.length);
      }
    }
    expect(changed.length, 'scheduler was a no-op on every witnessed fixture').toBeGreaterThan(0);
    console.log(`  scheduler changed bytes on: ${changed.join(', ')}`);
  });
});
