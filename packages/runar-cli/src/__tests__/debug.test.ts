// ---------------------------------------------------------------------------
// Tests for runar-cli/commands/debug.ts
//
// The debug command runs a REPL over stdin. These tests only cover the
// early argument / artifact validation paths that can be exercised without
// entering the REPL.
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

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
