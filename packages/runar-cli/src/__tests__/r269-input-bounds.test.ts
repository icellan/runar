/**
 * R-269 (CL-GAP-021): `verify`, `analyze` and `debug` read a user-supplied file
 * with no size bound, while `compile --from-ir` rejects an oversized one at the
 * CLI boundary.
 *
 * `compile` does it deliberately (commands/compile.ts:150-164): "reject
 * oversized IR files at the CLI boundary so the user gets a tier-agnostic,
 * byte-precise error before the compiler is even invoked". The other three
 * `readFileSync` and hand the result to `JSON.parse`, so a 2 GB file is a
 * process that allocates until the allocator or the OOM killer decides how the
 * command ends.
 *
 * A local CLI is not a server, and the bound is not protecting the user from
 * themselves. It is that these commands take a path, and a path is a thing that
 * arrives in a script, a Makefile, or a CI job that fetched an artifact from
 * somewhere. "It crashed with a JS heap out-of-memory after ninety seconds" is a
 * worse answer than "that file is 2 GB, the limit is 16 MiB".
 *
 * The test drives the real commands against a file just over the limit and
 * requires a bounded refusal, plus controls at a normal size so the bound cannot
 * be satisfied by refusing everything.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { InputLimits } from 'runar-ir-schema';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../../../..');
const CLI = join(ROOT, 'packages/runar-cli/src/bin.ts');

function loader(): string | null {
  for (const p of [
    join(ROOT, 'conformance/node_modules/tsx/dist/loader.mjs'),
    join(ROOT, 'node_modules/tsx/dist/loader.mjs'),
  ]) {
    if (existsSync(p)) return pathToFileURL(p).href;
  }
  return null;
}

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'r269-'));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

function run(args: string[]): { status: number | null; out: string } {
  const l = loader();
  if (l === null) throw new Error('no tsx loader');
  const res = spawnSync(process.execPath, ['--import', l, CLI, ...args], {
    cwd: ROOT,
    encoding: 'utf-8',
    timeout: 180_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  return { status: res.status, out: `${res.stdout ?? ''}${res.stderr ?? ''}` };
}

/** A JSON file one byte past the IR limit, cheap to build. */
function oversizedJson(name: string): string {
  const p = join(dir, name);
  const filler = 'a'.repeat(InputLimits.MAX_IR_BYTES);
  writeFileSync(p, `{"script":"00","pad":"${filler}"}`);
  return p;
}

const SMALL_ARTIFACT = {
  version: 'runar-v1.0.0-rc.1',
  compilerVersion: '1.0.0-rc.1',
  contractName: 'Tiny',
  abi: { constructor: { params: [] }, methods: [] },
  script: '5100',
  asm: 'OP_1 OP_0',
  buildTimestamp: '2023-11-14T22:13:20Z',
};

describe('R-269: every command that reads a file bounds it', () => {
  it('the CLI runs at all (without this the refusals below prove nothing)', () => {
    const { out } = run(['--help']);
    expect(out).toMatch(/analyze|compile/);
  });

  /** Each command takes its file in a different position. */
  const CASES: Array<{ cmd: string; argv: (file: string) => string[] }> = [
    { cmd: 'verify', argv: (f) => ['verify', 'deadbeef', '--artifact', f, '--network', 'testnet'] },
    { cmd: 'analyze', argv: (f) => ['analyze', f] },
    { cmd: 'debug', argv: (f) => ['debug', f] },
  ];

  for (const { cmd, argv } of CASES) {
    it(`${cmd} refuses an oversized input by size, not by running out of memory`, () => {
      const big = oversizedJson(`big-${cmd}.json`);
      const { status, out } = run(argv(big));
      expect(status, `${cmd} accepted a file over the limit`).not.toBe(0);
      expect(
        out,
        `${cmd} failed for some other reason; the message should name the size ` +
          `and the limit:\n${out.slice(0, 400)}`,
      ).toMatch(/limit is \d+|exceeds|too large/i);
    });
  }

  it('verify still reads a normal artifact', () => {
    const p = join(dir, 'small.json');
    writeFileSync(p, JSON.stringify(SMALL_ARTIFACT));
    const { out } = run(['verify', 'deadbeef', '--artifact', p, '--network', 'testnet']);
    // It may well report the artifact as invalid for other reasons; what it must
    // NOT do is refuse it for size.
    expect(out).not.toMatch(/limit is \d+/);
  });

  it('analyze still reads a normal hex file', () => {
    const p = join(dir, 'small.hex');
    writeFileSync(p, '5100\n');
    const { out } = run(['analyze', p]);
    expect(out).not.toMatch(/limit is \d+/);
  });
});
