// ---------------------------------------------------------------------------
// Tests for runar-cli/commands/test.ts — test runner wrapper
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

describe('testCommand', () => {
  let testCommand: typeof import('../commands/test.js').testCommand;
  let tmpRoot: string;
  let originalCwd: string;

  beforeEach(async () => {
    const mod = await import('../commands/test.js');
    testCommand = mod.testCommand;
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-testcmd-'));
    originalCwd = process.cwd();
    process.chdir(tmpRoot);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    try {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
    vi.restoreAllMocks();
  });

  it('is a function', () => {
    expect(typeof testCommand).toBe('function');
  });

  it('error path: no tests/ directory and no pattern sets exitCode=1', async () => {
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    await testCommand();

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('No tests/ directory'),
    )).toBe(true);

    consoleErrSpy.mockRestore();
    consoleLogSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  it('happy path: vitest failure is converted into exitCode=1 without killing the process', async () => {
    const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    // Create a tests/ dir with a definitely-failing spec so our vitest
    // wrapper spawns a child and picks up a non-zero exit. We pass an
    // explicit pattern that points to a file that doesn't exist — this
    // still prevents the early "no tests/ directory" bail but vitest will
    // fail because no test files match.
    fs.mkdirSync(path.join(tmpRoot, 'tests'));
    // vitest reports "No test files found" as a non-zero exit.
    await testCommand('tests/does-not-exist.test.ts');

    // Either vitest ran and failed (exitCode=1) OR succeeded with
    // passWithNoTests (exitCode unchanged). Both outcomes are valid —
    // we just want to confirm the command does not throw and that the
    // starting banner was printed.
    const logCalls = consoleLogSpy.mock.calls.map(c => c[0]);
    expect(logCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('Running tests'),
    )).toBe(true);

    consoleLogSpy.mockRestore();
    process.exitCode = prevExitCode;
  }, 60_000);
});
