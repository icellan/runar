import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileFromANF, loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import { BrokenTier, IR_TIER_IDS, Tier, buildIrTiers } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-055 — on the `--ir` path, a public method that reaches an output intrinsic
 * (add_output / add_raw_output / add_data_output) only through a `method_call`
 * to a private method is refused with ONE diagnostic in all seven tiers.
 *
 * Before the fix every tier already refused (fail-closed) but with an internal
 * stack-lowering error ("_codePart not found on stack" and per-tier variants),
 * which names neither the cause nor the remedy. The source path inlines private
 * helpers before ANF, so the output intrinsic always sits in the public method;
 * hand-written IR can break that invariant, and --ir has no delegation support.
 *
 * Proves: each of the three intrinsics, delegated via method_call, is refused
 * by every built tier (and TS in process) with the shared sentence, and that
 * no tier emits a script. Does NOT prove: that a differently shaped delegation
 * (nested helpers, helpers reached through control flow) is refused with this
 * exact text, nor any acceptance path; none is added.
 */
const ERROR =
  'output intrinsics must be called from the public method or an inlined helper; --ir method_call delegation is not supported';

const CORPUS = JSON.parse(
  readFileSync(join(__dirname, 'n055-ir-output-delegation-cases.json'), 'utf8'),
) as { cases: Array<{ name: string; ir: unknown }> };

const DIR = mkdtempSync(join(tmpdir(), 'n055-ir-output-delegation-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name}.ir.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

function runIr(tier: Tier, input: string): { status: number; out: string; diag: string } {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(input)];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run: ${res.error.message}`);
  if (res.signal !== null) throw new BrokenTier(`${where} killed by ${res.signal}`);
  if (res.status === null) throw new BrokenTier(`${where}: no exit status`);
  return {
    status: res.status,
    out: (res.stdout ?? '').trim(),
    diag: `${res.stderr ?? ''}\n${res.stdout ?? ''}`,
  };
}

describe('N-055: --ir output-intrinsic delegation via method_call (all 7 tiers)', () => {
  it('the corpus holds the three intrinsics', () => {
    expect(CORPUS.cases.map((c) => c.name).sort()).toEqual([
      'add-data-output-delegated',
      'add-output-delegated',
      'add-raw-output-delegated',
    ]);
  });

  it('the matrix names all seven IR-capable CLI tiers', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (isCiEnv(process.env)) expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  for (const c of CORPUS.cases) {
    it(`ts refuses ${c.name} with the shared diagnostic (in process)`, () => {
      let message = '<accepted>';
      try {
        compileFromANF(loadANFFromJSON(JSON.stringify(c.ir)), { disableConstantFolding: true });
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toContain(ERROR);
    });
  }

  for (const tier of available) {
    for (const c of CORPUS.cases) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic`, () => {
        const { status, out, diag } = runIr(tier, write(c.name, c.ir));
        expect(status, `${tier.id} accepted ${c.name} (emitted "${out}")`).not.toBe(0);
        expect(diag).toContain(ERROR);
      });
    }
  }
});
