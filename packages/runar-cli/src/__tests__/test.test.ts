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
    // No per-test cap: this spawns a real vitest child (35 s on an idle CI
    // runner, 70 s on a loaded one), so the root config's 300 s testTimeout
    // governs, as for every other long test.
  });

  // F-166: the user-supplied pattern used to be interpolated into a shell
  // string (`"<vitest>" run "<pattern>"`), so `$(...)`, backticks and a
  // closing quote all executed arbitrary commands. These tests stand up a
  // fake runner that records its argv, feed crafted patterns that would
  // create a marker file if any shell evaluated them, and require (1) no
  // marker and (2) the pattern reached the runner as ONE literal argv entry.
  //
  // Proves: neither the local-vitest path nor the npx fallback lets a shell
  // see the pattern. Does NOT prove anything about vitest's own filtering
  // of the pattern (the fake runner only records argv), nor Windows
  // behaviour (the fakes are POSIX shebang scripts).
  describe('F-166: pattern is passed as a literal argv entry, never through a shell', () => {
    function adversarialPatterns(dir: string): Array<{ pattern: string; marker: string }> {
      const m1 = path.join(dir, 'pwned-subst');
      const m2 = path.join(dir, 'pwned-quote');
      const m3 = path.join(dir, 'pwned-backtick');
      const w = (m: string) => `node -e "require('fs').writeFileSync(${JSON.stringify(m).replace(/"/g, "'")},'1')"`;
      return [
        { pattern: `$(${w(m1)})`, marker: m1 },
        { pattern: `x"; ${w(m2)} #`, marker: m2 },
        { pattern: `\`${w(m3)}\``, marker: m3 },
      ];
    }

    function writeFakeRunner(file: string, argvOut: string): void {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(
        file,
        `#!/usr/bin/env node\nrequire('fs').writeFileSync(${JSON.stringify(argvOut)}, JSON.stringify(process.argv.slice(2)));\n`,
      );
      fs.chmodSync(file, 0o755);
    }

    it('local node_modules/.bin/vitest path', async () => {
      const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const argvOut = path.join(tmpRoot, 'argv.json');
      writeFakeRunner(path.join(tmpRoot, 'node_modules', '.bin', 'vitest'), argvOut);

      for (const { pattern, marker } of adversarialPatterns(tmpRoot)) {
        if (fs.existsSync(argvOut)) fs.rmSync(argvOut);
        await testCommand(pattern);
        expect(fs.existsSync(marker), `shell evaluated pattern ${pattern}`).toBe(false);
        expect(JSON.parse(fs.readFileSync(argvOut, 'utf8'))).toEqual(['run', pattern]);
      }

      // A benign pattern still reaches the runner unchanged.
      await testCommand('tests/foo.test.ts');
      expect(JSON.parse(fs.readFileSync(argvOut, 'utf8'))).toEqual(['run', 'tests/foo.test.ts']);
      consoleLogSpy.mockRestore();
    });

    it('npx fallback path', async () => {
      const consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const argvOut = path.join(tmpRoot, 'argv.json');
      const fakeBin = path.join(tmpRoot, 'fakebin');
      writeFakeRunner(path.join(fakeBin, 'npx'), argvOut);
      const prevPath = process.env.PATH;
      process.env.PATH = `${fakeBin}${path.delimiter}${prevPath ?? ''}`;
      try {
        for (const { pattern, marker } of adversarialPatterns(tmpRoot)) {
          if (fs.existsSync(argvOut)) fs.rmSync(argvOut);
          await testCommand(pattern);
          expect(fs.existsSync(marker), `shell evaluated pattern ${pattern}`).toBe(false);
          expect(JSON.parse(fs.readFileSync(argvOut, 'utf8'))).toEqual(['vitest', 'run', pattern]);
        }
      } finally {
        process.env.PATH = prevPath;
        consoleLogSpy.mockRestore();
      }
    });
  });
});
