/**
 * N-070 — `requireOutputP2PKH` delegated to a private helper compiles in every
 * tier, to the same bytes as the direct call.
 *
 * The intrinsic auto-injects a `_serialisedOutputs` witness param into the
 * method it is lowered in. Every tier's ANF lowering inlined a private helper
 * at the call site only when the helper emitted outputs, so a helper that only
 * called `requireOutputP2PKH` stayed a `method_call` and the witness param
 * never reached the public spending method. All seven tiers refused the
 * program (six in stack lowering — "method parameter '_serialisedOutputs' is
 * not on the stack" — and Go one gate earlier, "public method 'payBond' must
 * end with an assert() call"). Fail-closed, but a legitimate terminal covenant
 * could not be factored into a helper.
 *
 * ORACLE. The contract below is `examples/ts/intent-output-p2pkh` with its one
 * statement moved into a helper, so the fold-OFF bytes each tier emits are
 * compared against that fixture's checked-in seven-tier golden — an existing,
 * witnessed artifact, not this tier against its peers. Fold-ON has no golden,
 * so there every tier is compared against the TypeScript reference.
 *
 * PROVES: each built tier compiles the helper form and emits the golden bytes
 * (fold OFF), all agree with TypeScript (fold ON), and each lists the witness
 * on the PUBLIC method's ABI exactly as the golden's ANF does — the ABI is what
 * an SDK reads to build the unlock, and it drifted across tiers once (ce8ee231).
 * DOES NOT PROVE: that the bytes spend on chain (the Spend.validate test in
 * packages/runar-testing/src/__tests__/n070-require-output-p2pkh-via-helper-spend.test.ts
 * does), that the F-075 refusals still hold (conformance/negatives N153-N155
 * do), or anything about `extractPrevOutputScript` in a helper.
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

/** `examples/ts/intent-output-p2pkh/IntentOutputP2PKH.runar.ts`, body moved into a helper. */
const HELPER_SOURCE = `import { StatefulSmartContract, ByteString, requireOutputP2PKH } from 'runar-lang';

class IntentOutputP2PKH extends StatefulSmartContract {
  readonly bondPKH: ByteString;
  readonly bondAmount: bigint;
  count: bigint;

  constructor(bondPKH: ByteString, bondAmount: bigint, count: bigint) {
    super(bondPKH, bondAmount, count);
    this.bondPKH = bondPKH;
    this.bondAmount = bondAmount;
    this.count = count;
  }

  private assertBond(): void {
    requireOutputP2PKH(0n, this.bondPKH, this.bondAmount);
  }

  public payBond() {
    this.assertBond();
  }
}
`;

const GOLDEN_HEX = readFileSync(
  join(ROOT, 'conformance/tests/intent-output-p2pkh/expected-script.hex'),
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

const srcPath = join(mkdtempSync(join(tmpdir(), 'n070-')), 'IntentOutputP2PKH.runar.ts');
writeFileSync(srcPath, HELPER_SOURCE);

async function tsHex(disableConstantFolding: boolean): Promise<string> {
  const { compile } = await import('runar-compiler');
  const r = compile(HELPER_SOURCE, { fileName: 'IntentOutputP2PKH.runar.ts', disableConstantFolding });
  expect(r.success, r.diagnostics.map((d) => d.message).join('\n')).toBe(true);
  return r.artifact!.script;
}

function nativeHex(tier: (typeof TIERS)[number], foldFlags: string[]): string {
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

/** The seven-tier ANF golden's `payBond` param list. */
const GOLDEN_PARAMS = (
  JSON.parse(
    readFileSync(join(ROOT, 'conformance/tests/intent-output-p2pkh/expected-ir.json'), 'utf-8'),
  ) as { methods: Array<{ name: string; params?: Array<{ name: string }> }> }
).methods
  .find((m) => m.name === 'payBond')!
  .params!.map((p) => p.name);

/** `payBond`'s ABI param names from the tier's deployable artifact. */
function nativeAbiParams(tier: (typeof TIERS)[number]): string[] {
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
  return (a.abi.methods.find((m) => m.name === 'payBond')?.params ?? []).map((p) => p.name);
}

describe('N-070: requireOutputP2PKH in a private helper, every tier', () => {
  it('at least two native tiers are built (a one-tier run proves nothing)', () => {
    expect(available.length).toBeGreaterThanOrEqual(2);
  });

  it('typescript: fold OFF emits the intent-output-p2pkh golden', async () => {
    expect(await tsHex(true)).toBe(GOLDEN_HEX);
  }, 300_000);

  it('typescript: payBond ABI carries the witness, as the golden ANF does', async () => {
    const { compile } = await import('runar-compiler');
    const r = compile(HELPER_SOURCE, { fileName: 'IntentOutputP2PKH.runar.ts' });
    const m = r.artifact!.abi.methods.find((x: { name: string }) => x.name === 'payBond')!;
    expect(m.params.map((p: { name: string }) => p.name)).toEqual(GOLDEN_PARAMS);
    expect(GOLDEN_PARAMS).toContain('_serialisedOutputs');
  }, 300_000);

  for (const tier of TIERS) {
    const maybe = available.includes(tier) ? it : it.skip;
    maybe(`${tier.id}: fold OFF emits the intent-output-p2pkh golden`, () => {
      expect(nativeHex(tier, ['--disable-constant-folding'])).toBe(GOLDEN_HEX);
    }, 300_000);
    maybe(`${tier.id}: fold ON agrees with the TypeScript reference`, async () => {
      expect(nativeHex(tier, [])).toBe(await tsHex(false));
    }, 300_000);
    maybe(`${tier.id}: payBond ABI carries the witness, as the golden ANF does`, () => {
      expect(nativeAbiParams(tier)).toEqual(GOLDEN_PARAMS);
    }, 300_000);
  }
});
