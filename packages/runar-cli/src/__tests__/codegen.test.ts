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

  it('rejects unsupported language with process.exit', async () => {
    const mod = await import('../commands/codegen.js');
    codegenCommand = mod.codegenCommand;

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: string | number | null) => {
      throw new Error('process.exit called');
    });

    await expect(
      codegenCommand(['some-file.json'], { lang: 'python' }),
    ).rejects.toThrow('process.exit called');

    const errCalls = consoleSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes("'python' is not yet supported"),
    )).toBe(true);

    consoleSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it('rejects empty file list after expansion with process.exit', async () => {
    const mod = await import('../commands/codegen.js');
    codegenCommand = mod.codegenCommand;

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: string | number | null) => {
      throw new Error('process.exit called');
    });

    // A glob pattern that matches nothing
    await expect(
      codegenCommand(['/tmp/nonexistent-runar-glob-*.json'], { lang: 'ts' }),
    ).rejects.toThrow('process.exit called');

    const errCalls = consoleSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('no artifact files matched'),
    )).toBe(true);

    consoleSpy.mockRestore();
    exitSpy.mockRestore();
  });

  it('accepts "ts" as a valid language without immediately exiting', async () => {
    const mod = await import('../commands/codegen.js');
    codegenCommand = mod.codegenCommand;

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((_code?: string | number | null) => {
      throw new Error('process.exit called');
    });

    // Pass a non-existent file (not a glob). It will pass the lang check
    // but fail at the file-existence check. The key thing is that it does
    // NOT fail with "language not supported".
    try {
      await codegenCommand(
        ['/tmp/nonexistent-runar-artifact.json'],
        { lang: 'ts' },
      );
    } catch {
      // Expected — will fail on file not found or missing runar-sdk import
    }

    const errCalls = consoleSpy.mock.calls.map(c => c[0]);
    const hasLangError = errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('is not yet supported'),
    );
    expect(hasLangError).toBe(false);

    consoleSpy.mockRestore();
    exitSpy.mockRestore();
  });
});
