/**
 * N-315 — `extractPrevOutputScript` delegated to a private helper compiles in
 * every tier, to the same bytes as the direct call.
 *
 * The intrinsic auto-injects a `_prevOutScript_<i>` witness param into the
 * method it is lowered in. N-070 taught every tier's ANF lowering to inline a
 * private helper that calls `requireOutputP2PKH`, but nothing flagged a helper
 * that calls `extractPrevOutputScript`, so it stayed a `method_call` and the
 * witness param sat on the helper's own ANF method. All seven tiers refused the
 * program in stack lowering ("method parameter '_prevOutScript_0' is not on the
 * stack"). Fail-closed, but the intrinsic could not be factored into a helper.
 *
 * ORACLE. The contract below is `examples/ts/intent-prev-output-script` with
 * its two intrinsic statements moved into a helper — once directly, once
 * through a second helper (the flag is transitive) — so the fold-OFF bytes each
 * tier emits are compared against that fixture's checked-in seven-tier golden,
 * an existing witnessed artifact, not this tier against its peers. Fold-ON has
 * no golden, so there every tier is compared against the TypeScript reference.
 *
 * PROVES: each built tier compiles both helper forms and emits the golden bytes
 * (fold OFF), agrees with TypeScript (fold ON), and lists the witness on the
 * PUBLIC method's ABI exactly as the golden's ANF does.
 * DOES NOT PROVE: that the bytes spend on chain (the Spend.validate test in
 * packages/runar-testing/src/__tests__/n315-extract-prev-output-script-via-helper-spend.test.ts
 * does), or a helper whose parameters feed the intrinsic (N-070's commit notes
 * that a parameterised helper evaluates its arguments before the inlined body,
 * so its bytes match a direct form only when that form reads them first).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
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

const PREAMBLE = `import { StatefulSmartContract, ByteString, assert, len, extractPrevOutputScript } from 'runar-lang';

class IntentPrevOutputScript extends StatefulSmartContract {
  readonly expectedHash: ByteString;
  count: bigint;

  constructor(expectedHash: ByteString, count: bigint) {
    super(expectedHash, count);
    this.expectedHash = expectedHash;
    this.count = count;
  }
`;

/** `examples/ts/intent-prev-output-script`, both intrinsic statements moved into a helper. */
const HELPER_SOURCE = `${PREAMBLE}
  private checkBound(): void {
    const s = extractPrevOutputScript(0n, this.expectedHash);
    assert(len(s) > 0n);
  }

  public bind() {
    this.checkBound();
    this.count = this.count + 1n;
  }
}
`;

/** The same, one helper further away: the flag must be transitive. */
const NESTED_SOURCE = `${PREAMBLE}
  private checkBoundInner(): void {
    const s = extractPrevOutputScript(0n, this.expectedHash);
    assert(len(s) > 0n);
  }

  private checkBound(): void {
    this.checkBoundInner();
  }

  public bind() {
    this.checkBound();
    this.count = this.count + 1n;
  }
}
`;

const GOLDEN_HEX = readFileSync(
  join(ROOT, 'conformance/tests/intent-prev-output-script/expected-script.hex'),
  'utf-8',
).trim();

function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

const TIERS = [
  { id: 'go', binary: findGoBinary(), cwd: join(ROOT, 'compilers/go') },
  { id: 'rust', binary: findRustBinary(), cwd: join(ROOT, 'compilers/rust') },
  { id: 'python', binary: findPythonBinary(), cwd: join(ROOT, 'compilers/python') },
  { id: 'ruby', binary: findRubyBinary(), cwd: join(ROOT, 'compilers/ruby') },
  { id: 'zig', binary: findZigBinary(), cwd: join(ROOT, 'compilers/zig') },
  { id: 'java', binary: findJavaBinary(), cwd: join(ROOT, 'compilers/java') },
];
const available = TIERS.filter((t) => t.binary !== null && existsSync(t.cwd));

const SOURCES = [
  { id: 'helper', source: HELPER_SOURCE },
  { id: 'nested helper', source: NESTED_SOURCE },
];

const tmp = mkdtempSync(join(tmpdir(), 'n315-'));
const srcPaths = new Map<string, string>();
SOURCES.forEach((s, i) => {
  const dir = join(tmp, String(i));
  mkdirSync(dir);
  const p = join(dir, 'IntentPrevOutputScript.runar.ts');
  writeFileSync(p, s.source);
  srcPaths.set(s.id, p);
});

async function tsHex(source: string, disableConstantFolding: boolean): Promise<string> {
  const { compile } = await import('runar-compiler');
  const r = compile(source, { fileName: 'IntentPrevOutputScript.runar.ts', disableConstantFolding });
  expect(r.success, r.diagnostics.map((d) => d.message).join('\n')).toBe(true);
  return r.artifact!.script;
}

function nativeHex(tier: (typeof TIERS)[number], srcPath: string, foldFlags: string[]): string {
  const { cmd, args } = splitCmd(tier.binary);
  const res = spawnSync(cmd!, [...args, '--source', srcPath, '--hex', ...foldFlags], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: 300_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  expect(res.status, `${tier.id} refused: ${(res.stderr || res.stdout || '').slice(0, 400)}`).toBe(0);
  return (res.stdout ?? '').trim();
}

/** The seven-tier ANF golden's `bind` param list. */
const GOLDEN_PARAMS = (
  JSON.parse(
    readFileSync(join(ROOT, 'conformance/tests/intent-prev-output-script/expected-ir.json'), 'utf-8'),
  ) as { methods: Array<{ name: string; params?: Array<{ name: string }> }> }
).methods
  .find((m) => m.name === 'bind')!
  .params!.map((p) => p.name);

/** `bind`'s ABI param names from the tier's deployable artifact. */
function nativeAbiParams(tier: (typeof TIERS)[number], srcPath: string): string[] {
  const { cmd, args } = splitCmd(tier.binary);
  const artPath = join(dirname(srcPath), `${tier.id}-artifact.json`);
  const argv = tier.id === 'java' ? ['--source', srcPath, '--emit-artifact', artPath] : ['--source', srcPath];
  const res = spawnSync(cmd!, [...args, ...argv], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: 300_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  expect(res.status, `${tier.id} refused: ${(res.stderr || res.stdout || '').slice(0, 400)}`).toBe(0);
  const json = tier.id === 'java' ? readFileSync(artPath, 'utf-8') : (res.stdout ?? '');
  const a = JSON.parse(json) as { abi: { methods: Array<{ name: string; params?: Array<{ name: string }> }> } };
  return (a.abi.methods.find((m) => m.name === 'bind')?.params ?? []).map((p) => p.name);
}

describe('N-315: extractPrevOutputScript in a private helper, every tier', () => {
  it('at least two native tiers are built (a one-tier run proves nothing)', () => {
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  it('the golden ANF puts the witness on bind', () => {
    expect(GOLDEN_PARAMS).toContain('_prevOutScript_0');
  });

  for (const s of SOURCES) {
    const srcPath = srcPaths.get(s.id)!;

    it(`typescript (${s.id}): fold OFF emits the intent-prev-output-script golden`, async () => {
      expect(await tsHex(s.source, true)).toBe(GOLDEN_HEX);
    }, 300_000);

    it(`typescript (${s.id}): bind ABI carries the witness, as the golden ANF does`, async () => {
      const { compile } = await import('runar-compiler');
      const r = compile(s.source, { fileName: 'IntentPrevOutputScript.runar.ts' });
      expect(r.success, r.diagnostics.map((d) => d.message).join('\n')).toBe(true);
      const m = r.artifact!.abi.methods.find((x: { name: string }) => x.name === 'bind')!;
      expect(m.params.map((p: { name: string }) => p.name)).toEqual(GOLDEN_PARAMS);
    }, 300_000);

    for (const tier of TIERS) {
      const maybe = available.includes(tier) ? it : it.skip;
      maybe(`${tier.id} (${s.id}): fold OFF emits the intent-prev-output-script golden`, () => {
        expect(nativeHex(tier, srcPath, ['--disable-constant-folding'])).toBe(GOLDEN_HEX);
      }, 300_000);
      maybe(`${tier.id} (${s.id}): fold ON agrees with the TypeScript reference`, async () => {
        expect(nativeHex(tier, srcPath, [])).toBe(await tsHex(s.source, false));
      }, 300_000);
      maybe(`${tier.id} (${s.id}): bind ABI carries the witness, as the golden ANF does`, () => {
        expect(nativeAbiParams(tier, srcPath)).toEqual(GOLDEN_PARAMS);
      }, 300_000);
    }
  }
});
