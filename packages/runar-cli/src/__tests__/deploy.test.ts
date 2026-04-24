// ---------------------------------------------------------------------------
// Tests for runar-cli/commands/deploy.ts
//
// These exercise top-level argument validation on deploy. Checksum-level
// WIF decoding is covered separately in deploy-decodeWIF.test.ts.
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

describe('deployCommand', () => {
  let deployCommand: typeof import('../commands/deploy.js').deployCommand;

  beforeAll(async () => {
    const mod = await import('../commands/deploy.js');
    deployCommand = mod.deployCommand;
  }, 60_000);

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('is a function', () => {
    expect(typeof deployCommand).toBe('function');
  });

  it('error path: invalid network sets exitCode=1', async () => {
    const mod = await import('../commands/deploy.js');
    deployCommand = mod.deployCommand;

    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    await deployCommand('does-not-matter.json', {
      network: 'regtest',
      key: 'irrelevant',
      satoshis: '1000',
    });

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('Invalid network'),
    )).toBe(true);

    consoleErrSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  it('error path: missing artifact sets exitCode=1', async () => {
    const mod = await import('../commands/deploy.js');
    deployCommand = mod.deployCommand;

    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    const fake = path.join(os.tmpdir(), `runar-deploy-missing-${Date.now()}.json`);
    await deployCommand(fake, {
      network: 'testnet',
      key: 'ignored-because-artifact-is-missing',
      satoshis: '1000',
    });

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('Failed to load artifact'),
    )).toBe(true);

    consoleErrSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  it('happy path: loads artifact and rejects bad WIF with exitCode=1', async () => {
    const mod = await import('../commands/deploy.js');
    deployCommand = mod.deployCommand;

    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    // Minimal valid artifact JSON.
    const artifact = {
      contractName: 'NoOp',
      script: '00',
      asm: 'OP_0',
      abi: { constructor: { params: [] }, methods: [] },
    };
    const tmp = path.join(os.tmpdir(), `runar-deploy-art-${Date.now()}.json`);
    fs.writeFileSync(tmp, JSON.stringify(artifact));

    try {
      await deployCommand(tmp, {
        network: 'testnet',
        key: 'ThisIsNotAValidWIF',
        satoshis: '1000',
      });
    } finally {
      fs.unlinkSync(tmp);
    }

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    // Could be "Invalid private key" (WIF decode failure).
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('Invalid private key'),
    )).toBe(true);

    // Verify the artifact was actually read (header printed).
    const logCalls = consoleLogSpy.mock.calls.map(c => c[0]);
    expect(logCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('Deploying contract'),
    )).toBe(true);

    consoleLogSpy.mockRestore();
    consoleErrSpy.mockRestore();
    process.exitCode = prevExitCode;
  });
});
