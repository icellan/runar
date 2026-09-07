// ---------------------------------------------------------------------------
// Tests for the experimental size-optimizer flags on the TS CLI:
//   --stack-scheduler <current|liveness>
//   --ec-constant-pool
//
// Both change emitted bytes when enabled and MUST be inert when absent, since
// the checked-in goldens, `conformance/script-size-baseline.json` and the
// cross-tier hex parity gate all assume the default path.
//
// See docs/experiments/script-size-optimizer-results.md.
// ---------------------------------------------------------------------------

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

/** The smallest contract whose bytes come entirely from the generic scheduler. */
const ARITHMETIC = `
import { SmartContract, assert } from 'runar-lang';

class Arithmetic extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) {
    super(target);
    this.target = target;
  }
  public verify(a: bigint, b: bigint): void {
    const sum: bigint = a + b;
    const diff: bigint = a - b;
    const prod: bigint = a * b;
    const quot: bigint = a / b;
    const result: bigint = sum + diff + prod + quot;
    assert(result === this.target);
  }
}
`;

let workDir: string;

beforeAll(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runar-cli-exp-'));
});

afterAll(() => {
  if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
});

describe('experimental size-optimizer flags', () => {
  let compileCommand: typeof import('../commands/compile.js').compileCommand;

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
    ({ compileCommand } = await import('../commands/compile.js'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /** Compile ARITHMETIC with the given options and return the printed hex. */
  async function hexWith(options: Record<string, unknown>, tag: string): Promise<string> {
    const srcPath = path.join(workDir, `Arithmetic-${tag}.runar.ts`);
    fs.writeFileSync(srcPath, ARITHMETIC);
    const outDir = path.join(workDir, `out-${tag}`);
    fs.mkdirSync(outDir, { recursive: true });

    const writeSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const originalExitCode = process.exitCode;

    await compileCommand([srcPath], { output: outDir, hex: true, ...options });

    const printed = writeSpy.mock.calls.map(c => String(c[0])).join('').trim();
    process.exitCode = originalExitCode;
    writeSpy.mockRestore();
    return printed;
  }

  it('is inert when no experimental flag is passed', async () => {
    const bare = await hexWith({}, 'bare');
    const explicit = await hexWith({ stackScheduler: 'current' }, 'explicit');
    expect(bare).toBe(explicit);
    // The shipping schedule for this contract; also the checked-in golden for
    // conformance/tests/arithmetic modulo the constructor placeholder.
    expect(bare).toBe('6e9352795279945379537995547a547a96537a537a937b937c93009c');
    expect(bare.length / 2).toBe(28);
  });

  it('--stack-scheduler liveness reschedules and shrinks', async () => {
    const out = await hexWith(
      { stackScheduler: 'liveness', acknowledgeSingleTierSchedule: true },
      'liveness',
    );
    expect(out).toBe('6e936b6e946b6e956b966c6c6c939393009c');
    expect(out.length / 2).toBe(18);
  });

  it('refuses liveness without the single-tier acknowledgement', async () => {
    // The mode exists in this compiler ONLY, and it moves emitted bytes — which
    // shifts the constructorSlots offsets and codeSeparatorIndex the SDKs read
    // back out of the artifact. A contract compiled this way has a funding
    // address no other tier reproduces, so reaching it must be deliberate.
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const originalExitCode = process.exitCode;

    const srcPath = path.join(workDir, 'Arithmetic-unack.runar.ts');
    fs.writeFileSync(srcPath, ARITHMETIC);
    const outDir = path.join(workDir, 'out-unack');
    await compileCommand([srcPath], {
      output: outDir, stackScheduler: 'liveness',
    } as Parameters<typeof compileCommand>[1]);

    expect(process.exitCode).toBe(1);
    const said = errSpy.mock.calls.flat().join('\n');
    expect(said).toContain('TypeScript compiler ONLY');
    expect(said).toContain('--acknowledge-single-tier-schedule');
    // And it must not have written an artifact.
    expect(fs.existsSync(outDir) && fs.readdirSync(outDir).length > 0).toBe(false);

    process.exitCode = originalExitCode;
    vi.restoreAllMocks();
  });

  it('rejects an unknown scheduler mode instead of silently using the default', async () => {
    // A benchmark run that quietly measured the shipping compiler while
    // reporting an experiment is worse than a crash.
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const originalExitCode = process.exitCode;

    const srcPath = path.join(workDir, 'Arithmetic-bad.runar.ts');
    fs.writeFileSync(srcPath, ARITHMETIC);
    const outDir = path.join(workDir, 'out-bad');
    fs.mkdirSync(outDir, { recursive: true });

    await compileCommand([srcPath], { output: outDir, hex: true, stackScheduler: 'bogus' });

    const errors = errSpy.mock.calls.map(c => String(c[0])).join('\n');
    expect(errors).toMatch(/unknown mode 'bogus'/);
    process.exitCode = originalExitCode;
  });

  it('--ec-constant-pool is inert on a contract with no EC operations', async () => {
    const bare = await hexWith({}, 'nopool');
    const pooled = await hexWith({ ecConstantPool: true }, 'pool');
    expect(pooled).toBe(bare);
  });

  it('--ec-reduction-sinking is inert on a contract with no EC operations', async () => {
    const bare = await hexWith({}, 'nosink');
    const sunk = await hexWith({ ecConstantPool: true, ecReductionSinking: true }, 'sink');
    expect(sunk).toBe(bare);
  });
});
