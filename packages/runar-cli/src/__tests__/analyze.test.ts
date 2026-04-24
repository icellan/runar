// ---------------------------------------------------------------------------
// Tests for runar-cli/commands/analyze.ts
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

describe('analyzeCommand', () => {
  let analyzeCommand: typeof import('../commands/analyze.js').analyzeCommand;

  beforeAll(async () => {
    // Pre-warm the dynamic imports so the first real test doesn't pay the
    // ~1-5s cold-import cost inside its own timeout budget.
    const mod = await import('../commands/analyze.js');
    analyzeCommand = mod.analyzeCommand;
  }, 60_000);

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('is a function', () => {
    expect(typeof analyzeCommand).toBe('function');
  });

  it('happy path: analyzes a P2PKH hex string without errors', async () => {
    const mod = await import('../commands/analyze.js');
    analyzeCommand = mod.analyzeCommand;

    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    // Standard P2PKH: OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG
    await analyzeCommand('76a90088ac', { severity: 'info' });

    // Should not flag any errors, exit code should not be set to 1.
    expect(process.exitCode).toBe(0);
    const logCalls = consoleSpy.mock.calls.map(c => c[0]);
    expect(logCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('Script Analysis'),
    )).toBe(true);

    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  it('error path: unreadable / malformed input hex surfaces error', async () => {
    const mod = await import('../commands/analyze.js');
    analyzeCommand = mod.analyzeCommand;

    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    // Artifact JSON that does NOT contain a "script" field: the resolver
    // should throw, the command should catch it and set exitCode to 1.
    const tmpFile = path.join(os.tmpdir(), `runar-analyze-bad-${Date.now()}.json`);
    fs.writeFileSync(tmpFile, JSON.stringify({ unrelated: 'value' }));
    try {
      await analyzeCommand(tmpFile, { severity: 'info' });
    } finally {
      fs.unlinkSync(tmpFile);
    }

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('Error'),
    )).toBe(true);

    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  it('json mode emits JSON-shaped output', async () => {
    const mod = await import('../commands/analyze.js');
    analyzeCommand = mod.analyzeCommand;

    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    await analyzeCommand('76a90088ac', { json: true, severity: 'info' });

    const logCalls = logSpy.mock.calls.map(c => c[0]);
    const jsonLine = logCalls.find(
      (msg: unknown) => typeof msg === 'string' && msg.trim().startsWith('{'),
    );
    expect(jsonLine).toBeDefined();

    logSpy.mockRestore();
    process.exitCode = prevExitCode;
  });
});
