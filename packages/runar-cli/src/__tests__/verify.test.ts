// ---------------------------------------------------------------------------
// Tests for runar-cli/commands/verify.ts
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

describe('verifyCommand', () => {
  let verifyCommand: typeof import('../commands/verify.js').verifyCommand;

  beforeAll(async () => {
    const mod = await import('../commands/verify.js');
    verifyCommand = mod.verifyCommand;
  }, 60_000);

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('is a function', () => {
    expect(typeof verifyCommand).toBe('function');
  });

  it('error path: invalid network sets exitCode=1', async () => {
    const mod = await import('../commands/verify.js');
    verifyCommand = mod.verifyCommand;

    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    await verifyCommand('0'.repeat(64), {
      artifact: '/tmp/no.json',
      network: 'regtest',
    });

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('Invalid network'),
    )).toBe(true);

    consoleErrSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  it('error path: missing artifact file sets exitCode=1', async () => {
    const mod = await import('../commands/verify.js');
    verifyCommand = mod.verifyCommand;

    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    const fake = path.join(os.tmpdir(), `runar-verify-missing-${Date.now()}.json`);
    await verifyCommand('0'.repeat(64), {
      artifact: fake,
      network: 'testnet',
    });

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('Failed to load artifact'),
    )).toBe(true);

    consoleErrSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  it('happy path: loads a valid artifact and prints the verification header', async () => {
    const mod = await import('../commands/verify.js');
    verifyCommand = mod.verifyCommand;

    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    const artifact = {
      contractName: 'TestContract',
      script: '76a90088ac',
      asm: 'OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG',
      abi: { constructor: { params: [] }, methods: [] },
    };
    const tmp = path.join(os.tmpdir(), `runar-verify-art-${Date.now()}.json`);
    fs.writeFileSync(tmp, JSON.stringify(artifact));

    try {
      // Verify will try to fetch the tx and probably fail (no network) —
      // that's fine; we just assert the command reached the header stage
      // and gracefully set exitCode on fetch failure.
      await verifyCommand('0'.repeat(64), {
        artifact: tmp,
        network: 'testnet',
      });
    } finally {
      fs.unlinkSync(tmp);
    }

    const logCalls = consoleLogSpy.mock.calls.map(c => c[0]);
    expect(logCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('Verifying contract'),
    )).toBe(true);

    consoleLogSpy.mockRestore();
    consoleErrSpy.mockRestore();
    process.exitCode = prevExitCode;
  }, 60_000);
});
