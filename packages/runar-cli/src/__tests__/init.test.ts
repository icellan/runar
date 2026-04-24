// ---------------------------------------------------------------------------
// Tests for runar-cli/commands/init.ts — project scaffolding
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

type Lang = 'ts' | 'zig' | 'go' | 'rust' | 'python' | 'ruby';

// Expected files per-language scaffold. The key check is that each scaffold
// produces at least one .runar.* contract file plus a matching test file,
// and that neither is empty.
const EXPECTED: Record<Lang, { contract: string; test: string }> = {
  ts:     { contract: 'contract/P2PKH.runar.ts', test: 'contract/P2PKH.test.ts' },
  zig:    { contract: 'src/P2PKH.runar.zig',     test: 'src/P2PKH_test.zig'     },
  go:     { contract: 'Counter.runar.go',        test: 'Counter_test.go'        },
  rust:   { contract: 'Counter.runar.rs',        test: 'tests/Counter_test.rs'  },
  python: { contract: 'Counter.runar.py',        test: 'test_counter.py'        },
  ruby:   { contract: 'Counter.runar.rb',        test: 'counter_spec.rb'        },
};

describe('initCommand', () => {
  let initCommand: typeof import('../commands/init.js').initCommand;
  let tmpRoot: string;
  let originalCwd: string;

  beforeEach(async () => {
    const mod = await import('../commands/init.js');
    initCommand = mod.initCommand;
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-init-test-'));
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

  it('error path: unsupported language sets exitCode=1', async () => {
    const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const prevExitCode = process.exitCode;
    process.exitCode = 0;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await initCommand('proj', { lang: 'cobol' as any });

    expect(process.exitCode).toBe(1);
    const errCalls = consoleErrSpy.mock.calls.map(c => c[0]);
    expect(errCalls.some(
      (msg: unknown) => typeof msg === 'string' && msg.includes('Unsupported language'),
    )).toBe(true);

    consoleErrSpy.mockRestore();
    process.exitCode = prevExitCode;
  });

  for (const lang of ['ts', 'zig', 'go', 'rust', 'python', 'ruby'] as const) {
    it(`happy path: scaffolds a ${lang} project with non-empty contract + test files`, async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const consoleErrSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const projectName = `${lang}-sample-project`;
      await initCommand(projectName, { lang });

      const projectDir = path.join(tmpRoot, projectName);
      expect(fs.existsSync(projectDir)).toBe(true);

      const { contract, test } = EXPECTED[lang];
      const contractPath = path.join(projectDir, contract);
      const testPath = path.join(projectDir, test);

      expect(fs.existsSync(contractPath)).toBe(true);
      expect(fs.existsSync(testPath)).toBe(true);

      const contractContent = fs.readFileSync(contractPath, 'utf-8');
      const testContent = fs.readFileSync(testPath, 'utf-8');
      expect(contractContent.length).toBeGreaterThan(0);
      expect(testContent.length).toBeGreaterThan(0);

      consoleSpy.mockRestore();
      consoleErrSpy.mockRestore();
    });
  }
});
