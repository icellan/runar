import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import {
  CONSENSUS_SPEND_CONTEXT,
  newConsensusSpend,
} from '../../packages/runar-testing/src/consensus-spend.js';
import { compile, compileFromANF, loadANFFromJSON } from '../../packages/runar-compiler/src/index.js';
import {
  BrokenTier,
  Tier,
  buildIrTiers,
  buildSourceTiers,
  compileHex,
  verdict,
} from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * N-065 / N-060 — compiler-reserved names, all seven tiers, one diagnostic.
 *
 * Several passes mint names into the namespace user identifiers live in (ANF
 * temps `t<digits>`, `__merge$<digits>`; FixedArray slots and hoisted temps;
 * stack lowering's `_codePart`, `__param_*`, `__shadowed_*`, `_pub_<digits>`;
 * the auto-injected parameters), and every later pass resolves names by string
 * equality. A user name spelled like a minted one aliased the two values:
 *
 *   let t2: bigint = p; assert(p > 0n); if (c) { t2 = p; } assert(t2 + 1n === 1n);
 *
 * compiled (folding OFF, every tier) to a script that accepts unlock(1, false),
 * which the source rejects — the final guard read the temp `t2` (= 0). On the
 * `--ir` path, a binding named `_codePart` in a stateful method made the state
 * continuation PICK that binding instead of stack lowering's `_codePart` slot
 * (N-060). User decision R26: reserve and refuse, one shared sentence, no byte
 * change for any accepted program.
 *
 * The corpus is `reserved-names-cases.json` (source: one case per declaration
 * position and per reserved family, on all nine surfaces, each with a renamed
 * twin; ir: one field of a P2PK control renamed per case). Every tier must
 * refuse every case with the case's exact sentence, and compile every renamed
 * twin to the SAME bytes as the reference tier.
 *
 * What this proves: all seven tiers refuse each case with the one diagnostic
 * and emit no script; the renamed twins and the accepted programs (a stateless
 * contract's own `txPreimage`; ANF temp names as IR bindings) compile, byte-
 * identical across tiers; the Spend oracle sees the pre-fix IfStale script
 * accept the attack its renamed twin rejects.
 * What it does NOT prove: that every name any future pass mints is in the
 * reserved set — a new minted family must be added to all seven helpers.
 */

interface SourceCase { name: string; file: string; src: string; twin: string; error: string }
interface IrCase { name: string; ir: unknown; error: string }
const CORPUS = JSON.parse(readFileSync(join(__dirname, 'reserved-names-cases.json'), 'utf8')) as {
  source: { accept: Array<{ name: string; file: string; src: string }>; cases: SourceCase[] };
  ir: { accept: Array<{ name: string; ir: unknown }>; cases: IrCase[] };
};

const DIR = mkdtempSync(join(tmpdir(), 'n065-reserved-names-'));
let seq = 0;
const writeFile = (fileName: string, content: string): string => {
  const d = join(DIR, String(seq++));
  mkdirSync(d);
  const p = join(d, fileName);
  writeFileSync(p, content);
  return p;
};

const SOURCE_TIERS: Tier[] = buildSourceTiers().filter((t) => t.id !== 'ts' && t.cmd !== null);
// F-342: `buildIrTiers()` now includes `ts` (it has a real --from-ir CLI
// mode), but this file already covers `ts` on the --ir path directly via
// `tsIrHex` above (no subprocess, no tsx cold start) — same reason
// SOURCE_TIERS excludes it. Filtering it out of IR_TIERS keeps that one
// `ts`-via-CLI redundant spawn out of this file's loops rather than silently
// doubling every IR assertion below.
const IR_TIERS: Tier[] = buildIrTiers().filter((t) => t.id !== 'ts' && t.cmd !== null);

/** Run a tier's CLI; no interpretation beyond "it ran to completion". */
function run(tier: Tier, input: string): { status: number; out: string; diag: string } {
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

/** Spend `lockingHex` with the push-only `unlockingHex` under consensus rules. */
function spends(lockingHex: string, unlockingHex: string): boolean {
  try {
    return newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
      otherInputs: [],
      outputs: [],
    }).validate();
  } catch {
    return false;
  }
}

const tsSourceHex = (src: string, file: string): string => {
  const r = compile(src, { fileName: file });
  if (!r.success || !r.scriptHex) throw new Error(JSON.stringify(r.diagnostics));
  return r.scriptHex.toLowerCase();
};
const tsIrHex = (ir: unknown): string =>
  compileFromANF(loadANFFromJSON(JSON.stringify(ir))).scriptHex.toLowerCase();

describe('N-065 / N-060: compiler-reserved names (all 7 tiers)', () => {
  // -- the oracle sees the miscompile the refusal removes ---------------------

  it('the pre-fix IfStale script accepts unlock(1, false); its renamed twin rejects it', () => {
    // Every tier emitted this for IfStale (local `t2`) with folding OFF.
    const preFix = '767600877c51879b69785279007c78a0697b637b677b757668778b519c77';
    // unlock(p = 1, c = false): 1 + 1 === 1 is false, so the source rejects.
    expect(spends(preFix, '5100')).toBe(true);
    const twin = CORPUS.source.cases.find((c) => c.name === 'ts-local-t2-ifstale')!.twin;
    const twinHex = tsSourceHex(twin, 'IfStaleTwin.runar.ts');
    expect(twinHex).toBe('767600877c51879b6978527900a0697c637c67777668778b519c');
    expect(spends(twinHex, '5100')).toBe(false);
    expect(spends(twinHex, '5000')).toBe(false); // p = 0 fails p > 0
  });

  // -- vacuity guards ----------------------------------------------------------

  it('the corpus covers every position, family and surface', () => {
    expect(CORPUS.source.cases.length).toBeGreaterThanOrEqual(30);
    expect(CORPUS.ir.cases.length).toBeGreaterThanOrEqual(10);
    const exts = new Set(CORPUS.source.cases.map((c) => c.file.replace(/^.*?\.runar\./, '')));
    expect([...exts].sort()).toEqual(['go', 'java', 'move', 'py', 'rb', 'rs', 'sol', 'ts', 'zig']);
    for (const c of [...CORPUS.source.cases, ...CORPUS.ir.cases]) {
      expect(c.error, c.name).toMatch(/^'[^']+' is reserved for compiler-generated names and cannot be used as an identifier$/);
    }
    for (const c of CORPUS.source.cases) expect(c.twin, c.name).not.toBe(c.src);
  });

  it('every native tier is built (strict in CI, ">=2" locally)', () => {
    if (isCiEnv(process.env)) {
      expect(SOURCE_TIERS.map((t) => t.id).sort()).toEqual(['go', 'java', 'python', 'ruby', 'rust', 'zig']);
      expect(IR_TIERS.map((t) => t.id).sort()).toEqual(['go', 'java', 'python', 'ruby', 'rust', 'zig']);
    }
    expect(SOURCE_TIERS.length).toBeGreaterThanOrEqual(2);
    expect(IR_TIERS.length).toBeGreaterThanOrEqual(2);
  });

  // -- source path -------------------------------------------------------------

  for (const c of CORPUS.source.cases) {
    it(`ts refuses ${c.name} with the shared diagnostic`, () => {
      const r = compile(c.src, { fileName: c.file });
      expect(r.success).toBe(false);
      expect(r.diagnostics.map((d) => d.message)).toContain(c.error);
    });

    for (const tier of SOURCE_TIERS) {
      it(`${tier.id} refuses ${c.name} with the shared diagnostic`, () => {
        const { status, out, diag } = run(tier, writeFile(c.file, c.src));
        expect(status, `${tier.id} accepted ${c.name} (emitted "${out}")`).not.toBe(0);
        expect(diag).toContain(c.error);
      });
    }

    it(`every tier compiles the renamed twin of ${c.name} to the same bytes`, () => {
      const want = tsSourceHex(c.twin, c.file);
      const input = writeFile(c.file, c.twin);
      for (const tier of SOURCE_TIERS) {
        expect(compileHex(tier, input), `${tier.id} vs ts on the twin of ${c.name}`).toBe(want);
      }
    });
  }

  for (const a of CORPUS.source.accept) {
    it(`every tier accepts ${a.name}`, () => {
      tsSourceHex(a.src, a.file);
      const input = writeFile(a.file, a.src);
      for (const tier of SOURCE_TIERS) expect(verdict(tier, input), tier.id).toBe('accepted');
    });
  }

  // -- --ir path ---------------------------------------------------------------

  for (const a of CORPUS.ir.accept) {
    it(`every tier compiles the IR ${a.name} to the same bytes`, () => {
      const want = tsIrHex(a.ir);
      expect(want).toBe('00ac');
      const input = writeFile(`${a.name}.ir.json`, JSON.stringify(a.ir));
      for (const tier of IR_TIERS) expect(compileHex(tier, input), tier.id).toBe(want);
    });
  }

  for (const c of CORPUS.ir.cases) {
    it(`ts refuses the IR ${c.name} with the shared diagnostic`, () => {
      expect(() => tsIrHex(c.ir)).toThrow(c.error);
    });

    for (const tier of IR_TIERS) {
      it(`${tier.id} refuses the IR ${c.name} with the shared diagnostic`, () => {
        const { status, out, diag } = run(tier, writeFile(`${c.name}.ir.json`, JSON.stringify(c.ir)));
        expect(status, `${tier.id} accepted ${c.name} (emitted "${out}")`).not.toBe(0);
        expect(diag).toContain(c.error);
      });
    }
  }
});
