// ---------------------------------------------------------------------------
// Tests for runar-cli/commands/debug.ts
//
// The debug command runs a REPL over stdin. The debugCommand tests cover the
// early argument / artifact validation paths that can be exercised without
// entering the REPL; the F-221 block drives the REPL via a bin.ts subprocess.
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

describe('debugCommand', () => {
  let debugCommand: typeof import('../commands/debug.js').debugCommand;

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('is a function', async () => {
    const mod = await import('../commands/debug.js');
    debugCommand = mod.debugCommand;
    expect(typeof debugCommand).toBe('function');
  });

  it('error path: missing artifact file sets exitCode=1', async () => {
    const mod = await import('../commands/debug.js');
    debugCommand = mod.debugCommand;

    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    const fake = path.join(os.tmpdir(), `runar-debug-nonexistent-${Date.now()}.json`);
    await debugCommand(fake, {});

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('artifact not found'),
    )).toBe(true);

    consoleErrSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  it('error path: malformed artifact JSON sets exitCode=1', async () => {
    const mod = await import('../commands/debug.js');
    debugCommand = mod.debugCommand;

    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    const tmp = path.join(os.tmpdir(), `runar-debug-bad-${Date.now()}.json`);
    fs.writeFileSync(tmp, '{not valid json');
    try {
      await debugCommand(tmp, {});
    } finally {
      fs.unlinkSync(tmp);
    }

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('failed to parse artifact'),
    )).toBe(true);

    consoleErrSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  it('error path: artifact missing compiled script sets exitCode=1', async () => {
    const mod = await import('../commands/debug.js');
    debugCommand = mod.debugCommand;

    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    // Valid JSON, but no `script` field.
    const tmp = path.join(os.tmpdir(), `runar-debug-noscript-${Date.now()}.json`);
    fs.writeFileSync(
      tmp,
      JSON.stringify({
        contractName: 'Empty',
        asm: '',
        abi: { constructor: { params: [] }, methods: [] },
      }),
    );
    try {
      await debugCommand(tmp, {});
    } finally {
      fs.unlinkSync(tmp);
    }

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('no compiled script'),
    )).toBe(true);

    consoleErrSpy.mockRestore();
    consoleLogSpy.mockRestore();
    process.exitCode = prevExitCode;
  });
});

// ---------------------------------------------------------------------------
// F-221: the exit status of a debug session must reflect the script verdict.
//
// Proves: driving the real CLI (bin.ts) as a subprocess with `c` on stdin
// and then EOF, a script that runs to a failing verdict (OP_0 → falsy top
// of stack) exits non-zero while still printing "Script failed.", and the
// passing control (OP_1) still exits 0 — so the check cannot be satisfied
// by failing every session.
// Does NOT prove: anything about a session quit before the script reaches
// a verdict (that stays exit 0 — no verdict was produced), nor anything
// about the correctness of the underlying ScriptVM.
// ---------------------------------------------------------------------------
describe('debug exit status (F-221)', () => {
  const HERE = path.dirname(fileURLToPath(import.meta.url));
  const ROOT = path.resolve(HERE, '../../../..');
  const CLI = path.join(ROOT, 'packages/runar-cli/src/bin.ts');

  function loader(): string {
    for (const p of [
      path.join(ROOT, 'conformance/node_modules/tsx/dist/loader.mjs'),
      path.join(ROOT, 'node_modules/tsx/dist/loader.mjs'),
    ]) {
      if (fs.existsSync(p)) return pathToFileURL(p).href;
    }
    throw new Error('no tsx loader');
  }

  function runDebug(scriptHex: string): { status: number | null; out: string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-debug-exit-'));
    const artifact = path.join(dir, 'a.json');
    fs.writeFileSync(artifact, JSON.stringify({
      contractName: 'T',
      script: scriptHex,
      asm: '',
      abi: { constructor: { params: [] }, methods: [] },
    }));
    try {
      const res = spawnSync(process.execPath, ['--import', loader(), CLI, 'debug', artifact], {
        cwd: ROOT,
        input: 'c\n',
        encoding: 'utf-8',
        timeout: 120_000,
      });
      return { status: res.status, out: `${res.stdout ?? ''}${res.stderr ?? ''}` };
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  it('a falsy script (OP_0) exits non-zero and reports the failure', () => {
    const { status, out } = runDebug('00');
    expect(out).toContain('Script failed.');
    expect(status).not.toBe(0);
  }, 150_000);

  it('a truthy script (OP_1) still exits 0', () => {
    const { status, out } = runDebug('51');
    expect(out).toContain('Script completed successfully.');
    expect(status).toBe(0);
  }, 150_000);
});
