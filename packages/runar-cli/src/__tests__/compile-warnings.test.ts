// ---------------------------------------------------------------------------
// CL-BUG-104: the TS CLI must not swallow validator warnings.
//
// `compile()` returns every diagnostic in `CompileResult.diagnostics`,
// warnings included (packages/runar-compiler/src/index.ts pushes
// `validationResult.warnings` and the issue-#109 `@embedAlways` DCE notice).
// compile.ts filtered for `severity === 'error'` and only on the *failure*
// path — so a successful compile printed nothing at all, and the SP1 FRI
// unsoundness disclosure, the DCE notices and the sighash advisories were
// invisible to anyone driving the compiler from the command line.
//
// Reference behaviour is the Rust (`compilers/rust/src/main.rs`:
// `eprintln!("warning: {}", w)`) and Zig (`compilers/zig/src/main.zig`:
// `printDiagnostics`) tiers: warnings go to stderr (console.error), one per
// line, prefixed `warning: `, and they change neither the exit code nor the
// bytes on stdout.
//
// The warning driven here is a real one — V26, "StatefulSmartContract has no
// mutable properties", emitted by 02-validate.ts. Nothing synthetic is
// injected.
// ---------------------------------------------------------------------------

import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const WARNING_SOURCE = `import { StatefulSmartContract, assert } from 'runar-lang';

export class WarnStateful extends StatefulSmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public unlock(x: bigint): void {
    assert(x < this.limit);
  }
}
`;

const CLEAN_SOURCE = `import { SmartContract, assert } from 'runar-lang';

export class CleanStateless extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public unlock(x: bigint): void {
    assert(x < this.limit);
  }
}
`;

describe('compileCommand — validator warnings', () => {
  let compileCommand: typeof import('../commands/compile.js').compileCommand;
  let tmpDir: string;

  beforeAll(async () => {
    const sourceEntry = path.resolve(process.cwd(), 'packages/runar-compiler/src/index.ts');
    if (fs.existsSync(sourceEntry)) {
      const { pathToFileURL } = await import('node:url');
      await import(pathToFileURL(sourceEntry).href);
    } else {
      await import('runar-compiler');
    }
  }, 60_000);

  beforeEach(async () => {
    const mod = await import('../commands/compile.js');
    compileCommand = mod.compileCommand;
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-cli-warn-'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function writeSource(name: string, body: string): string {
    const p = path.join(tmpDir, name);
    fs.writeFileSync(p, body);
    return p;
  }

  it('prints the validator warning to stderr on a successful compile', async () => {
    const src = writeSource('WarnStateful.runar.ts', WARNING_SOURCE);
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await compileCommand([src], { output: path.join(tmpDir, 'out') });

    const errLines = errSpy.mock.calls.map(c => String(c[0]));
    expect(
      errLines.some(l => l.includes('StatefulSmartContract has no mutable properties')),
      `validator warning did not reach stderr; got ${JSON.stringify(errLines)}`,
    ).toBe(true);
    expect(
      errLines.some(l => l.includes('warning: ')),
      `warning line must carry the 'warning: ' prefix used by Rust/Zig; got ${JSON.stringify(errLines)}`,
    ).toBe(true);
    // Advisory only: a warning must not fail the build.
    expect(process.exitCode).not.toBe(1);
  }, 60_000);

  // --parse-only is where the other six tiers print their warnings, because
  // their --parse-only runs parse + validate. N-415: the TS CLI's --parse-only
  // now runs the validate pass too (it passes `validateOnly` to compile()), so
  // the validator warning is reachable here and is printed like in the natives,
  // while stdout stays exactly the "parser ok" marker the conformance runner reads.
  it('prints the validator warning and the parser-ok marker in --parse-only mode', async () => {
    const src = writeSource('WarnStateful.runar.ts', WARNING_SOURCE);
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await compileCommand([src], { output: path.join(tmpDir, 'out'), parseOnly: true });

    const written = stdoutSpy.mock.calls.map(c => String(c[0])).join('');
    expect(written).toBe('parser ok\n');
    expect(process.exitCode).not.toBe(1);
    const errLines = errSpy.mock.calls.map(c => String(c[0]));
    expect(
      errLines.some(l => l.startsWith('warning: ') && l.includes('StatefulSmartContract has no mutable properties')),
      `validator warning did not reach stderr under --parse-only; got ${JSON.stringify(errLines)}`,
    ).toBe(true);
  }, 60_000);

  it('prints no warning line and exits 0 for a clean contract', async () => {
    const src = writeSource('CleanStateless.runar.ts', CLEAN_SOURCE);
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await compileCommand([src], { output: path.join(tmpDir, 'out') });

    const errLines = errSpy.mock.calls.map(c => String(c[0]));
    expect(
      errLines.some(l => l.includes('warning')),
      `clean compile must print no warning line; got ${JSON.stringify(errLines)}`,
    ).toBe(false);
    expect(process.exitCode).not.toBe(1);
  }, 60_000);

  it('leaves the emitted hex untouched — the warning rides stderr only', async () => {
    const src = writeSource('WarnStateful.runar.ts', WARNING_SOURCE);
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});

    await compileCommand([src], { output: path.join(tmpDir, 'out'), hex: true });

    const written = stdoutSpy.mock.calls.map(c => String(c[0])).join('');
    expect(written.trim()).toMatch(/^[0-9a-f]+$/);
    expect(written).not.toContain('warning');
  }, 60_000);
});
