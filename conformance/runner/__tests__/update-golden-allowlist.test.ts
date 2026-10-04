import { describe, it, expect, afterAll, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { shutdownJavaDaemon, updateGoldenFiles } from '../runner.js';

// F-051 (CL-BUG-100): `updateGoldenFiles` (the `--update-golden` path) ran the
// TS compiler on every fixture and wrote its output as the golden, without
// reading the fixture's source.json `compilers` allowlist. For a Go-only
// fixture (e.g. state-covenant, `compilers: ["go"]`) that overwrote the
// Go-verified golden with bytes from a tier no gate ever compares against it.
//
// What this proves: on a scratch fixture whose allowlist excludes TS, the
// golden-update path REFUSES with an error naming the fixture and the allowlist,
// and leaves both golden files byte-for-byte untouched; on a scratch fixture
// whose allowlist includes TS (and one with no allowlist) it still restamps
// the goldens from TS output, so the legitimate path keeps working.
// What it does not prove: that any real fixture's golden bytes are correct —
// this never runs against conformance/tests (goldens there are guarded by the
// golden-provenance gate), and it does not provide a non-TS way to restamp a
// Go-only fixture's golden.

const __dirname = dirname(fileURLToPath(import.meta.url));
const DONOR_SOURCE = resolve(__dirname, '../../../examples/ts/p2pkh/P2PKH.runar.ts');
const FIXTURE_NAME = 'scratch-update-golden';
const SENTINEL_IR = '{"sentinel":"pre-existing golden"}\n';
const SENTINEL_HEX = 'deadbeef\n';

const sandboxes: string[] = [];
afterEach(() => {
  while (sandboxes.length > 0) rmSync(sandboxes.pop()!, { recursive: true, force: true });
});
afterAll(async () => {
  await shutdownJavaDaemon();
});

/** A scratch fixture dir with sentinel goldens and the given `compilers` value (undefined = field absent). */
function makeFixture(compilers: string[] | undefined): string {
  const root = mkdtempSync(join(tmpdir(), 'runar-f051-'));
  sandboxes.push(root);
  const fixtureDir = join(root, 'tests', FIXTURE_NAME);
  mkdirSync(fixtureDir, { recursive: true });
  writeFileSync(join(fixtureDir, 'expected-ir.json'), SENTINEL_IR);
  writeFileSync(join(fixtureDir, 'expected-script.hex'), SENTINEL_HEX);
  const config: Record<string, unknown> = { sources: { '.runar.ts': DONOR_SOURCE } };
  if (compilers) config.compilers = compilers;
  writeFileSync(join(fixtureDir, 'source.json'), JSON.stringify(config, null, 2));
  return fixtureDir;
}

const goldens = (dir: string) => ({
  ir: readFileSync(join(dir, 'expected-ir.json'), 'utf-8'),
  hex: readFileSync(join(dir, 'expected-script.hex'), 'utf-8'),
});

describe('F-051: --update-golden respects the fixture compilers allowlist', () => {
  it('refuses to stamp a Go-only fixture from TS and leaves its goldens untouched', async () => {
    const dir = makeFixture(['go']);
    await expect(updateGoldenFiles(dir)).rejects.toThrow(/scratch-update-golden.*allowlist.*go/s);
    expect(goldens(dir)).toEqual({ ir: SENTINEL_IR, hex: SENTINEL_HEX });
  }, 60_000);

  it('refuses for a multi-tier allowlist that excludes TS', async () => {
    const dir = makeFixture(['go', 'rust']);
    await expect(updateGoldenFiles(dir)).rejects.toThrow(/scratch-update-golden/);
    expect(goldens(dir)).toEqual({ ir: SENTINEL_IR, hex: SENTINEL_HEX });
  }, 60_000);

  for (const [label, compilers] of [
    ['allowlist includes ts', ['ts', 'go']],
    ['no allowlist', undefined],
  ] as const) {
    it(`still restamps from TS when ${label}`, async () => {
      const dir = makeFixture(compilers ? [...compilers] : undefined);
      await updateGoldenFiles(dir);
      const g = goldens(dir);
      expect(g.ir).not.toBe(SENTINEL_IR);
      expect(g.hex).not.toBe(SENTINEL_HEX);
      expect(JSON.parse(g.ir).contractName).toBe('P2PKH');
      expect(g.hex.trim()).toMatch(/^[0-9a-f]+$/);
    }, 60_000);
  }
});
