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

  // Structural checks specific to the TS scaffold — the documented reference
  // layout in runar-tic-tac-toe. Any change to these expectations should be
  // mirrored in init.ts AND in the example README.
  it('ts: scaffolds a single root package.json with namespaced scripts', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await initCommand('ts-layout-check', { lang: 'ts' });
    const projectDir = path.join(tmpRoot, 'ts-layout-check');

    // Exactly one package.json at the root; no per-subdir installs.
    expect(fs.existsSync(path.join(projectDir, 'package.json'))).toBe(true);
    expect(fs.existsSync(path.join(projectDir, 'contract', 'package.json'))).toBe(false);
    expect(fs.existsSync(path.join(projectDir, 'contract', 'integration', 'package.json'))).toBe(false);

    const pkg = JSON.parse(fs.readFileSync(path.join(projectDir, 'package.json'), 'utf-8'));
    expect(pkg.scripts['contract:compile']).toMatch(/runar compile P2PKH\.runar\.ts -o artifacts/);
    expect(pkg.scripts['contract:test']).toBeDefined();
    expect(pkg.scripts['contract:test:integration']).toBeDefined();
    expect(pkg.scripts['contract:debug']).toMatch(/artifacts\/P2PKH\.runar\.json/);
    expect(pkg.scripts.codegen).toMatch(/contract\/artifacts\/P2PKH\.runar\.json/);

    // Dep versions bumped to current published line (^0.5.x).
    expect(pkg.dependencies['runar-lang']).toBe('^0.5.0');
    expect(pkg.dependencies['runar-sdk']).toBe('^0.5.0');
    expect(pkg.devDependencies['runar-cli']).toBe('^0.5.0');
    expect(pkg.devDependencies['runar-compiler']).toBe('^0.5.0');
    expect(pkg.devDependencies['runar-testing']).toBe('^0.5.0');
    expect(pkg.devDependencies['runar-ir-schema']).toBe('^0.5.0');
    // @types/node is required: the generated P2PKH.test.ts imports `node:fs`
    // / `node:path` / `node:url` and uses `import.meta.url`, which all need
    // the Node typings to typecheck cleanly.
    expect(pkg.devDependencies['@types/node']).toBeDefined();

    // fast-check was a dead dep — should not reappear.
    expect(pkg.devDependencies['fast-check']).toBeUndefined();

    consoleSpy.mockRestore();
  });

  it('ts: gitignores contract/artifacts/ and src/generated/', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await initCommand('ts-gitignore-check', { lang: 'ts' });
    const projectDir = path.join(tmpRoot, 'ts-gitignore-check');
    const gitignore = fs.readFileSync(path.join(projectDir, '.gitignore'), 'utf-8');
    expect(gitignore).toContain('contract/artifacts/');
    expect(gitignore).toContain('src/generated/');
    expect(gitignore).not.toContain('contract/*.runar.json');
    consoleSpy.mockRestore();
  });
});
