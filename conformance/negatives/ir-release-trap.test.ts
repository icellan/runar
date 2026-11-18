import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compile, compileFromANF, loadANFFromJSON, lowerToANF } from '../../packages/runar-compiler/src/index.js';
import { parse } from '../../packages/runar-compiler/src/passes/01-parse.js';
import { expandFixedArrays } from '../../packages/runar-compiler/src/passes/03b-expand-fixed-arrays.js';
import { BrokenTier, IR_TIER_IDS, Tier, buildIrTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * D18 on the `--ir` path, all seven tiers. `--ir` / compileFromANF skip
 * typecheck, where the source path refuses a public stateful method that writes
 * state and declares raw outputs but no `addOutput` (its state write would be
 * dropped and the contract's satoshis would leave with the spend). Every IR
 * loader re-derives the rule from the ANF: a public method of a
 * StatefulSmartContract program that reaches an `update_prop` and an
 * `add_raw_output` but no `add_output`, at any depth and through
 * `method_call`s to private methods, is refused with the source path's text.
 *
 * Corpus: conformance/negatives/dropped-continuation-cases.json. Each `refuse` source
 * is lowered by the TS lowerer with validate / typecheck skipped (exactly the
 * IR the pre-D18 frontend emitted); each `accept` source is the frontend's own
 * fold-OFF ANF and must compile to the TS bytes in every tier.
 *
 * Does not prove: the source path (gk-frontend-parity.test.ts), or that the
 * accepted shapes are spendable (packages/runar-sdk d18-dropped-continuation-spend).
 */

type Ir = Record<string, unknown>;
interface Case { name: string; file: string; src: string; error?: string }
const corpus = JSON.parse(readFileSync(join(__dirname, 'dropped-continuation-cases.json'), 'utf8')) as {
  refuse: Case[];
  accept: Case[];
};

const toWire = (anf: unknown): Ir =>
  JSON.parse(
    JSON.stringify(anf, (k, v: unknown) => {
      if (k === 'sourceLoc') return undefined;
      if (typeof v === 'bigint') {
        if (v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(v);
        return `${v}n`;
      }
      return v;
    }),
  ) as Ir;

function irOf(source: string, fileName: string): Ir {
  const r = compile(source, { fileName, disableConstantFolding: true });
  if (!r.success || !r.anf) throw new Error(`${fileName}: ${r.diagnostics.map((d) => d.message).join('; ')}`);
  return toWire(r.anf);
}

function loweredUnchecked(source: string, fileName: string): Ir {
  const parsed = parse(source, fileName);
  if (parsed.errors.some((e) => e.severity === 'error') || !parsed.contract) {
    throw new Error(parsed.errors.map((e) => e.message).join('; '));
  }
  // Pass 3b first, as the pipeline runs it (FixedArray element writes become
  // update_prop of the expanded siblings).
  const expanded = expandFixedArrays(parsed.contract);
  if (expanded.errors.length > 0) throw new Error(expanded.errors.map((e) => e.message).join('; '));
  return toWire(lowerToANF(expanded.contract));
}

const DIR = mkdtempSync(join(tmpdir(), 'd18-ir-'));
const write = (name: string, ir: unknown): string => {
  const p = join(DIR, `${name}.ir.json`);
  writeFileSync(p, JSON.stringify(ir));
  return p;
};

const TIERS: Tier[] = buildIrTiers();
const available = TIERS.filter((t) => t.cmd !== null);

const tsHex = (ir: unknown): string =>
  compileFromANF(loadANFFromJSON(JSON.stringify(ir)), { disableConstantFolding: true }).scriptHex.toLowerCase();

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
  return { status: res.status, out: (res.stdout ?? '').trim(), diag: `${res.stderr ?? ''}\n${res.stdout ?? ''}` };
}

const REFUSE = corpus.refuse.map((c) => ({ name: c.name, ir: loweredUnchecked(c.src, c.file), error: c.error! }));
const ACCEPT = corpus.accept.map((c) => ({ name: c.name, ir: irOf(c.src, c.file) }));

describe('D18: --ir refuses a state write with no state continuation (all 7 tiers)', () => {
  it('the matrix names all IR-capable tiers', () => {
    expect(TIERS.map((t) => t.id).sort()).toEqual([...IR_TIER_IDS].sort());
  });

  it('every IR-capable tier is built (strict in CI, ">=2" locally)', () => {
    const missing = TIERS.filter((t) => t.cmd === null).map((t) => t.id);
    if (isCiEnv(process.env)) expect(missing).toEqual([]);
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  it('the corpus is non-trivial and every refused IR writes state and declares a raw output', () => {
    expect(REFUSE.length).toBeGreaterThanOrEqual(5);
    expect(ACCEPT.length).toBeGreaterThanOrEqual(3);
    for (const c of REFUSE) {
      const s = JSON.stringify(c.ir);
      expect(s, c.name).toContain('"update_prop"');
      expect(s, c.name).toContain('"add_raw_output"');
      expect(s, c.name).not.toContain('"add_output"');
    }
  });

  for (const a of ACCEPT) {
    it(`all tiers compile ${a.name} to the same bytes as TS`, () => {
      const hex = tsHex(a.ir);
      const input = write(`accept-${a.name}`, a.ir);
      for (const tier of available) {
        expect(compileHex(tier, input), `${tier.id} on ${a.name}`).toBe(hex);
      }
    });
  }

  for (const c of REFUSE) {
    it(`ts refuses ${c.name} with the shared diagnostic`, () => {
      let message = '<accepted>';
      try {
        tsHex(c.ir);
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toContain(c.error);
    });
  }

  for (const tier of available) {
    for (const c of REFUSE) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic, without crashing`, () => {
        const { status, out, diag } = runIr(tier, write(`refuse-${c.name}`, c.ir));
        expect(status, `${tier.id} accepted ${c.name} (emitted "${out.slice(0, 80)}")`).not.toBe(0);
        expect(diag).not.toMatch(/panic|Traceback|Exception in thread|stack backtrace/);
        expect(diag).toContain(c.error);
      });
    }
  }
});
