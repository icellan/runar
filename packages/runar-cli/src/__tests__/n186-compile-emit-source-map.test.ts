// ---------------------------------------------------------------------------
// N-186: `runar compile --emit-source-map` was silently dropped on two paths.
//
//   * source input with --hex: the --hex branch `continue`d before the
//     --emit-source-map block, so the requested file was never written.
//   * --from-ir: the branch returned without ever reading the option.
//
// Both exited 0 having written nothing and printed no diagnostic. The Go,
// Rust, Python, Ruby, Java and Zig CLIs write the map on every one of these
// combinations; for an IR input there are no source locations, so they write
// the empty `{"mappings":[]}` wrapper. This CLI now does the same.
//
// What this proves: compileCommand writes a `{"mappings": [...]}` file for
// source+--hex, --from-ir, and --from-ir+--hex, keeps stdout as the hex under
// --hex, and a real source compile yields a non-empty mapping list.
// What it does not prove: any other tier's CLI (each has its own test).
// ---------------------------------------------------------------------------

import { describe, it, expect, beforeAll, afterAll, vi, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const P2PKH = `
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;
  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`;

let workDir: string;
let srcPath: string;
let irPath: string;

beforeAll(async () => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-cli-n186-'));
  srcPath = path.join(workDir, 'P2PKH.runar.ts');
  fs.writeFileSync(srcPath, P2PKH);
  const compilerMod = (await import('runar-compiler')) as unknown as {
    compile: (s: string, o?: { fileName?: string; disableConstantFolding?: boolean }) => { anf?: unknown };
  };
  const r = compilerMod.compile(P2PKH, { fileName: 'P2PKH.runar.ts', disableConstantFolding: true });
  irPath = path.join(workDir, 'P2PKH.anf.json');
  fs.writeFileSync(
    irPath,
    JSON.stringify(r.anf, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v)),
  );
}, 60_000);

afterAll(() => {
  if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function run(files: string[], opts: Record<string, unknown>, name: string) {
  const { compileCommand } = await import('../commands/compile.js');
  const smPath = path.join(workDir, `${name}.map.json`);
  const outDir = path.join(workDir, `out-${name}`);
  fs.mkdirSync(outDir, { recursive: true });
  const writes: string[] = [];
  vi.spyOn(process.stdout, 'write').mockImplementation((c) => {
    writes.push(String(c));
    return true;
  });
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
  const prevExit = process.exitCode;
  await compileCommand(files, {
    output: outDir,
    disableConstantFolding: true,
    emitSourceMap: smPath,
    ...opts,
  } as never);
  const exit = process.exitCode;
  process.exitCode = prevExit;
  return { smPath, stdout: writes.join(''), exit };
}

describe('compile --emit-source-map is never silently dropped (N-186)', () => {
  it('source + --hex writes the source map and prints the hex', async () => {
    const { smPath, stdout, exit } = await run([srcPath], { hex: true }, 'src-hex');
    expect(exit ?? 0).toBe(0);
    expect(stdout.trim()).toMatch(/^[0-9a-f]+$/);
    expect(fs.existsSync(smPath)).toBe(true);
    const sm = JSON.parse(fs.readFileSync(smPath, 'utf-8')) as { mappings: unknown[] };
    expect(sm.mappings.length).toBeGreaterThan(0);
  }, 60_000);

  it('--from-ir writes the (empty) source map', async () => {
    const { smPath, exit } = await run([], { fromIr: irPath }, 'ir-plain');
    expect(exit ?? 0).toBe(0);
    expect(fs.existsSync(smPath)).toBe(true);
    expect(JSON.parse(fs.readFileSync(smPath, 'utf-8'))).toEqual({ mappings: [] });
  }, 60_000);

  it('--from-ir --hex writes the (empty) source map and prints the hex', async () => {
    const { smPath, stdout, exit } = await run([], { fromIr: irPath, hex: true }, 'ir-hex');
    expect(exit ?? 0).toBe(0);
    expect(stdout.trim()).toMatch(/^[0-9a-f]+$/);
    expect(fs.existsSync(smPath)).toBe(true);
    expect(JSON.parse(fs.readFileSync(smPath, 'utf-8'))).toEqual({ mappings: [] });
  }, 60_000);
});
