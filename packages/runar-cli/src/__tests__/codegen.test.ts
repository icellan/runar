// ---------------------------------------------------------------------------
// Tests for runar-cli/commands/codegen.ts
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, afterEach } from 'vitest';

describe('codegenCommand', () => {
  let codegenCommand: typeof import('../commands/codegen.js').codegenCommand;

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('is a function', async () => {
    const mod = await import('../commands/codegen.js');
    codegenCommand = mod.codegenCommand;
    expect(typeof codegenCommand).toBe('function');
  });

  it('rejects unsupported language by setting process.exitCode', async () => {
    const mod = await import('../commands/codegen.js');
    codegenCommand = mod.codegenCommand;

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    await codegenCommand(['some-file.json'], { lang: 'fortran' });

    expect(process.exitCode).toBe(1);

    const errCalls = consoleSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes("'fortran' is not supported"),
    )).toBe(true);

    consoleSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  it('rejects empty file list after expansion by setting process.exitCode', async () => {
    const mod = await import('../commands/codegen.js');
    codegenCommand = mod.codegenCommand;

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    // A glob pattern that matches nothing
    await codegenCommand(['/tmp/nonexistent-runar-glob-*.json'], { lang: 'ts' });

    expect(process.exitCode).toBe(1);

    const errCalls = consoleSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('no artifact files matched'),
    )).toBe(true);

    consoleSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  it('accepts all supported languages without language error', async () => {
    const mod = await import('../commands/codegen.js');
    codegenCommand = mod.codegenCommand;

    for (const lang of ['ts', 'go', 'rust', 'python']) {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const prevExitCode = process.exitCode;
      process.exitCode = 0;

      // Pass a non-existent file (not a glob). It will pass the lang check
      // but fail at the file-existence check. The key thing is that it does
      // NOT fail with "is not supported".
      try {
        await codegenCommand(
          ['/tmp/nonexistent-runar-artifact.json'],
          { lang },
        );
      } catch {
        // Expected — may fail on missing runar-sdk import
      }

      const errCalls = consoleSpy.mock.calls.map(c => c[0]);
      const hasLangError = errCalls.some(
        (msg: unknown) => typeof msg === 'string' && msg.includes('is not supported'),
      );
      expect(hasLangError).toBe(false);

      consoleSpy.mockRestore();
      process.exitCode = prevExitCode;
    }
  });
});
