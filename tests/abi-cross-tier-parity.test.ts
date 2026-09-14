/**
 * The artifact ABI must be the same across every tier.
 *
 * Nothing compared it. The conformance suite compares ANF IR and script hex;
 * `expected-ir.json` carries contractName/methods/properties and no ABI at
 * all. The sdk-output suite compares deploy-time locking scripts, which do
 * not depend on a method's ABI params — and the two fixtures that DO carry
 * auto-injected witness params (intent-output-p2pkh, intent-prev-output-script)
 * are allowlisted out of it on exactly that reasoning. So the ABI was the one
 * artifact surface with no cross-tier gate anywhere.
 *
 * It diverged. `requireOutputP2PKH` / `extractPrevOutputScript` auto-inject
 * `_serialisedOutputs` and `_prevOutScript_<i>` during ANF lowering, while the
 * TypeScript assembler built the ABI from the AST's `method.params` — a
 * snapshot taken before that pass. Six tiers listed the witness param; the
 * TypeScript tier did not, so a caller reading a TS-produced artifact could
 * not know to supply the value the script reads, and the covenant's
 * `hash256(_serialisedOutputs) === extractOutputHash(txPreimage)` check failed
 * on a spend that looked correctly built. Fixed in ce8ee231; this is the guard
 * that would have caught it.
 *
 * The ANF is the authority for what the params ARE — it is byte-identical
 * across all seven tiers — so this test also pins each tier's ABI against the
 * checked-in seven-tier ANF golden, not merely against its peers. Tiers
 * agreeing with each other while all being wrong is the failure mode that
 * produced most of the findings on this branch.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  findGoBinary,
  findRustBinary,
  findPythonBinary,
  findZigBinary,
  findRubyBinary,
  findJavaBinary,
} from '../conformance/runner/runner.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Fixtures whose ANF golden carries an auto-injected witness param. */
const CASES = [
  {
    fixture: 'intent-output-p2pkh',
    source: 'examples/ts/intent-output-p2pkh/IntentOutputP2PKH.runar.ts',
    method: 'payBond',
  },
  {
    fixture: 'intent-prev-output-script',
    source: 'examples/ts/intent-prev-output-script/IntentPrevOutputScript.runar.ts',
    method: 'bind',
  },
] as const;

function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

interface Tier {
  id: string;
  binary: string | null;
  cwd: string;
  /** argv producing the deployable artifact; `toStdout` false means it lands at `artPath`. */
  artifact: (src: string, artPath: string) => { argv: string[]; toStdout: boolean };
}

const TIERS: Tier[] = [
  { id: 'go',     binary: findGoBinary(),     cwd: join(ROOT, 'compilers/go'),
    artifact: (src) => ({ argv: ['--source', src], toStdout: true }) },
  { id: 'rust',   binary: findRustBinary(),   cwd: join(ROOT, 'compilers/rust'),
    artifact: (src) => ({ argv: ['--source', src], toStdout: true }) },
  { id: 'python', binary: findPythonBinary(), cwd: join(ROOT, 'compilers/python'),
    artifact: (src) => ({ argv: ['--source', src], toStdout: true }) },
  { id: 'ruby',   binary: findRubyBinary(),   cwd: join(ROOT, 'compilers/ruby'),
    artifact: (src) => ({ argv: ['--source', src], toStdout: true }) },
  { id: 'zig',    binary: findZigBinary(),    cwd: join(ROOT, 'compilers/zig'),
    artifact: (src) => ({ argv: ['--source', src], toStdout: true }) },
  { id: 'java',   binary: findJavaBinary(),   cwd: join(ROOT, 'compilers/java'),
    artifact: (src, art) => ({ argv: ['--source', src, '--emit-artifact', art], toStdout: false }) },
];

function abiParamNames(json: string, method: string): string[] | null {
  try {
    const a = JSON.parse(json) as { abi?: { methods?: Array<{ name: string; params?: Array<{ name: string }> }> } };
    const m = (a.abi?.methods ?? []).find((x) => x.name === method);
    if (!m) return null;
    return (m.params ?? []).map((p) => p.name);
  } catch {
    return null;
  }
}

/** The seven-tier ANF golden's param list for `method`. */
function goldenParamNames(fixture: string, method: string): string[] {
  const g = JSON.parse(
    readFileSync(join(ROOT, 'conformance/tests', fixture, 'expected-ir.json'), 'utf-8'),
  ) as { methods: Array<{ name: string; params?: Array<{ name: string }> }> };
  const m = g.methods.find((x) => x.name === method);
  if (!m) throw new Error(`golden has no method '${method}'`);
  return (m.params ?? []).map((p) => p.name);
}

const available = TIERS.filter((t) => t.binary !== null && existsSync(t.cwd));

describe('artifact ABI params agree across tiers', () => {
  it('at least two native tiers are built (a one-tier run proves nothing)', () => {
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  for (const c of CASES) {
    it(`${c.fixture}: the TypeScript reference matches the seven-tier ANF golden`, async () => {
      const { compile } = await import('runar-compiler');
      const src = readFileSync(join(ROOT, c.source), 'utf-8');
      const r = compile(src, { fileName: `${c.fixture}.runar.ts` });
      expect(r.success, r.diagnostics.map((d) => d.message).join('\n')).toBe(true);
      const names = (r.artifact!.abi.methods.find((m) => m.name === c.method)!.params ?? []).map(
        (p: { name: string }) => p.name,
      );
      expect(names).toEqual(goldenParamNames(c.fixture, c.method));
    });

    for (const tier of TIERS) {
      const maybe = available.includes(tier) ? it : it.skip;
      maybe(`${c.fixture}: ${tier.id} matches the seven-tier ANF golden`, () => {
        const dir = mkdtempSync(join(tmpdir(), `abi-${tier.id}-`));
        const artPath = join(dir, 'artifact.json');
        const spec = tier.artifact(join(ROOT, c.source), artPath);
        const { cmd, args } = splitCmd(tier.binary);
        const res = spawnSync(cmd!, [...args, ...spec.argv], {
          cwd: tier.cwd,
          encoding: 'utf-8',
          timeout: 300_000,
          maxBuffer: 64 * 1024 * 1024,
        });
        expect(res.status, `${tier.id} failed: ${(res.stderr ?? '').slice(0, 400)}`).toBe(0);
        const json = spec.toStdout ? (res.stdout ?? '') : readFileSync(artPath, 'utf-8');
        const names = abiParamNames(json, c.method);
        expect(names, `${tier.id} produced no ABI method '${c.method}'`).not.toBeNull();
        expect(names).toEqual(goldenParamNames(c.fixture, c.method));
      });
    }
  }
});
