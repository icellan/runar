// ---------------------------------------------------------------------------
// Tests for runar-cli/commands/compile.ts
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest';

// We need to test the jsonWithBigInt helper. Since it's not exported, we
// re-implement the same logic and also test the compileCommand behavior
// for argument validation by importing and calling it with empty files.

// --- jsonWithBigInt is not exported, so we replicate it for unit testing ---
// If the module ever exports it, switch to a direct import.
function jsonWithBigInt(value: unknown): string {
  return JSON.stringify(
    value,
    (_key, v) => {
      if (typeof v === 'bigint') {
        return `${v}n`;
      }
      return v;
    },
    2,
  );
}

describe('jsonWithBigInt', () => {
  it('serializes a plain object without bigints unchanged', () => {
    const input = { name: 'test', count: 42 };
    const result = jsonWithBigInt(input);
    const parsed = JSON.parse(result);
    expect(parsed).toEqual(input);
  });

  it('serializes bigint values as strings with trailing "n"', () => {
    const input = { amount: 100n };
    const result = jsonWithBigInt(input);
    expect(result).toContain('"100n"');
    const parsed = JSON.parse(result);
    expect(parsed.amount).toBe('100n');
  });

  it('handles zero bigint', () => {
    const result = jsonWithBigInt({ val: 0n });
    expect(result).toContain('"0n"');
  });

  it('handles negative bigint', () => {
    const result = jsonWithBigInt({ val: -42n });
    expect(result).toContain('"-42n"');
  });

  it('handles very large bigint', () => {
    const big = 2n ** 256n;
    const result = jsonWithBigInt({ val: big });
    expect(result).toContain(`"${big}n"`);
  });

  it('handles nested objects with mixed types', () => {
    const input = {
      name: 'contract',
      params: [{ type: 'bigint', value: 999n }, { type: 'string', value: 'hello' }],
      nested: { deep: 123n },
    };
    const result = jsonWithBigInt(input);
    const parsed = JSON.parse(result);
    expect(parsed.params[0].value).toBe('999n');
    expect(parsed.params[1].value).toBe('hello');
    expect(parsed.nested.deep).toBe('123n');
  });

  it('handles arrays with bigints', () => {
    const result = jsonWithBigInt([1n, 2n, 3n]);
    const parsed = JSON.parse(result);
    expect(parsed).toEqual(['1n', '2n', '3n']);
  });

  it('handles null and undefined values gracefully', () => {
    const result = jsonWithBigInt({ a: null, b: 1n });
    const parsed = JSON.parse(result);
    expect(parsed.a).toBeNull();
    expect(parsed.b).toBe('1n');
  });

  it('produces indented output (2-space)', () => {
    const result = jsonWithBigInt({ a: 1 });
    // JSON.stringify with indent 2 produces lines starting with two spaces
    expect(result).toContain('  "a"');
  });
});

describe('compileCommand', () => {
  let compileCommand: typeof import('../commands/compile.js').compileCommand;

  beforeAll(async () => {
    // Warm the compiler import so the first real test doesn't pay ~1-5s
    // of cold-import cost against its own timeout budget. compile.ts
    // dynamically imports either the monorepo source entry or the
    // published "runar-compiler" package — pre-load both candidates.
    const fs = await import('node:fs');
    const path = await import('node:path');
    const { pathToFileURL } = await import('node:url');
    const sourceEntry = path.resolve(process.cwd(), 'packages/runar-compiler/src/index.ts');
    if (fs.existsSync(sourceEntry)) {
      await import(pathToFileURL(sourceEntry).href);
    } else {
      await import('runar-compiler');
    }
  }, 60_000);

  beforeEach(async () => {
    const mod = await import('../commands/compile.js');
    compileCommand = mod.compileCommand;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('is a function', () => {
    expect(typeof compileCommand).toBe('function');
  });

  it('handles empty file list without crashing', async () => {
    // Suppress console output during test
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    // With no files, should complete with 0 succeeded, 0 failed
    await compileCommand([], { output: '/tmp/runar-test-output' });

    // Should print the summary line
    const logCalls = consoleSpy.mock.calls.map(c => c[0]);
    expect(logCalls.some(msg => typeof msg === 'string' && msg.includes('0 succeeded'))).toBe(true);

    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
  });

  it('reports error for non-existent source file', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await compileCommand(
      ['/tmp/this-file-does-not-exist-runar-test.runar.ts'],
      { output: '/tmp/runar-test-output' },
    );

    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(msg => typeof msg === 'string' && msg.includes('Error reading file'))).toBe(true);

    consoleSpy.mockRestore();
    consoleErrSpy.mockRestore();
  });
});
