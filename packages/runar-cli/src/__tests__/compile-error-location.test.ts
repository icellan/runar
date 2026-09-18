// ---------------------------------------------------------------------------
// The TS CLI must print WHERE a compile error is, like the other six tiers do.
//
// `compile()` attaches a `loc` to the diagnostic — measured on the fixture
// below it is `{file, line: 25, column: 11}` — and `commands/compile.ts`
// mapped it away with `.map(d => d.message)` before printing. So the reference
// tier said:
//
//     - Undefined variable 'notDeclaredAnywhere'
//
// while every native tier said:
//
//     GhostDeadHelper.runar.ts:25:11: Undefined variable 'notDeclaredAnywhere'
//
// A 1-vs-6 divergence in the output a developer actually reads. It surfaced
// while fixing GK-BUG-009, where a cross-tier pin could not assert a location
// without reddening the reference tier for a renderer gap rather than a
// compiler one.
//
// The location is asserted as `file:line:column` — the format the six native
// tiers already emit — so the seven agree on shape, not merely on presence.
// ---------------------------------------------------------------------------
import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/** The error sits in an uncalled private helper, on line 9, column 11. */
const UNDEFINED_SOURCE = `import { SmartContract, assert } from 'runar-lang';

export class GhostLoc extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) { super(target); this.target = target; }

  private neverCalled(): bigint {
    assert(notDeclaredAnywhere === 1n);
    return 1n;
  }

  public unlock(seed: bigint): void {
    assert(seed === this.target);
  }
}
`;

describe('compileCommand — error locations', () => {
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
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-cli-loc-'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('prints file:line:column alongside the message', async () => {
    const src = path.join(tmpDir, 'GhostLoc.runar.ts');
    fs.writeFileSync(src, UNDEFINED_SOURCE);
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await compileCommand([src], { output: path.join(tmpDir, 'out') });
    const errLines = errSpy.mock.calls.map(c => String(c[0]));

    // Anti-vacuity: the diagnostic itself must have been printed at all.
    expect(
      errLines.some(l => l.includes("Undefined variable 'notDeclaredAnywhere'")),
      `the diagnostic never reached stderr; got ${JSON.stringify(errLines)}`,
    ).toBe(true);

    const located = errLines.find(l => l.includes("Undefined variable 'notDeclaredAnywhere'"))!;
    // The error is on line 9 of the source above, at the identifier's column.
    expect(
      /GhostLoc\.runar\.ts:9:\d+:/.test(located),
      `error line carries no file:line:column; the six native tiers print one. got: ${located}`,
    ).toBe(true);
  }, 60_000);

  it('still prints a diagnostic that genuinely has no location', async () => {
    // Not every diagnostic carries a `loc` — a parse failure before any node
    // exists has none. Those must still be shown, not dropped by a renderer
    // that assumes one.
    const src = path.join(tmpDir, 'Broken.runar.ts');
    fs.writeFileSync(src, 'this is not a contract at all\n');
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await compileCommand([src], { output: path.join(tmpDir, 'out') });
    const errLines = errSpy.mock.calls.map(c => String(c[0]));

    expect(
      errLines.some(l => l.trim().startsWith('-') && l.trim().length > 3),
      `an unlocated diagnostic was dropped entirely; got ${JSON.stringify(errLines)}`,
    ).toBe(true);
  }, 60_000);
});
