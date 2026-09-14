/**
 * Frontend parity: a bare field reference in a `.runar.java` contract.
 *
 * Java lets a method name an instance field without `this.`, and the repo's
 * own Java examples are written that way — `examples/java/.../P2PKH.runar.java`
 * says `assertThat(hash160(pubKey).equals(pubKeyHash))`. Those compile
 * everywhere because `.equals` never demands a type of its operand.
 *
 * Put the same bare reference somewhere a type IS demanded and the tiers split:
 *
 *     assertThat(price > strikePrice);   // strikePrice is @Readonly Bigint
 *
 *     TS, Zig, Java      accept, all three emitting 00a0
 *     Go, Rust, Python, Ruby   reject: "right operand of '>' must be bigint,
 *                                       got '<unknown>'"
 *
 * That is invariant 1 — "all seven compilers parse all nine surfaces, no
 * exceptions" — broken on real source: `examples/end2end-example/webapp/
 * PriceBet.runar.java` is written this way and could not be compiled by the
 * webapp's own Go tier at all.
 *
 * The `--parser-only` matrix cannot see it. The identifier parses fine in every
 * tier; the resolution to a contract property happens in TYPECHECK, which
 * `--parse-only` stops before. The four rejecting tiers were missing the
 * fallback the TS reference tier has carried since the Solidity frontend
 * needed it ("some frontends emit `pubKeyHash` instead of `this.pubKeyHash`").
 *
 * Every available tier must agree, and must agree with the `this.`-qualified
 * spelling, which is the same program.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { compile } from '../packages/runar-compiler/src/index.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function javaSource(comparison: string): string {
  return `package runar.probe;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class BareField extends SmartContract {
    @Readonly Bigint strikePrice;

    BareField(Bigint strikePrice) {
        super(strikePrice);
        this.strikePrice = strikePrice;
    }

    @Public
    void settle(Bigint price) {
        assertThat(${comparison});
    }
}
`;
}

interface Tier {
  name: string;
  /** Returns hex, or throws with the tier's diagnostic. */
  run: (path: string) => string;
}

/** Run a native CLI, returning its last stdout line. */
function cli(cmd: string, args: string[]): string {
  const out = execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const lines = out.trim().split('\n');
  return lines[lines.length - 1]!.trim();
}

function availableTiers(): Tier[] {
  const tiers: Tier[] = [
    {
      name: 'ts',
      run: path => {
        const source = require('node:fs').readFileSync(path, 'utf8');
        const result = compile(source, { fileName: 'BareField.runar.java', disableConstantFolding: true });
        const errors = result.diagnostics.filter(d => d.severity === 'error');
        if (errors.length) throw new Error(errors.map(e => e.message).join(' | '));
        return result.artifact!.script;
      },
    },
  ];

  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    tiers.push({
      name: 'go',
      run: p => {
        const out = execFileSync('go',
          ['run', '.', '--source', p, '--hex', '--disable-constant-folding'],
          { cwd: join(repoRoot, 'compilers/go'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
        const lines = out.trim().split('\n');
        return lines[lines.length - 1]!.trim();
      },
    });
  } catch {
    // No Go toolchain — the tier drops out rather than failing the suite.
  }

  const javaJar = join(repoRoot, 'compilers/java/build/libs/runar-java-compiler-1.0.0-rc.1.jar');
  if (existsSync(javaJar)) {
    try {
      execFileSync('java', ['-version'], { stdio: 'ignore' });
      tiers.push({
        name: 'java',
        run: p => cli('java', ['-jar', javaJar, '--source', p, '--hex', '--disable-constant-folding']),
      });
    } catch {
      // No JRE on PATH.
    }
  }

  const rust = join(repoRoot, 'compilers/rust/target/release/runar-compiler-rust');
  if (existsSync(rust)) {
    tiers.push({ name: 'rust', run: p => cli(rust, ['--source', p, '--hex', '--disable-constant-folding']) });
  }

  const zig = join(repoRoot, 'compilers/zig/zig-out/bin/runar-zig');
  if (existsSync(zig)) {
    tiers.push({ name: 'zig', run: p => cli(zig, ['--source', p, '--hex']) });
  }

  const rubyBin = join(repoRoot, 'compilers/ruby/bin/runar-compiler-ruby');
  if (existsSync(rubyBin)) {
    tiers.push({
      name: 'ruby',
      run: p => cli('ruby', [rubyBin, '--source', p, '--hex', '--disable-constant-folding']),
    });
  }

  if (existsSync(join(repoRoot, 'compilers/python/runar_compiler'))) {
    tiers.push({
      name: 'python',
      run: p => {
        const out = execFileSync('python3',
          ['-m', 'runar_compiler', '--source', p, '--hex', '--disable-constant-folding'],
          {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe'],
            env: { ...process.env, PYTHONPATH: join(repoRoot, 'compilers/python') },
          });
        const lines = out.trim().split('\n');
        return lines[lines.length - 1]!.trim();
      },
    });
  }

  return tiers;
}

describe('a bare field reference in .runar.java compiles the same everywhere', () => {
  let dir: string;
  let barePath: string;
  let qualifiedPath: string;
  const tiers = availableTiers();

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'runar-bare-field-'));
    barePath = join(dir, 'BareField.runar.java');
    qualifiedPath = join(dir, 'Qualified.runar.java');
    writeFileSync(barePath, javaSource('price > strikePrice'));
    writeFileSync(qualifiedPath, javaSource('price > this.strikePrice'));
  });

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('drives enough tiers to be meaningful (anti-vacuity)', () => {
    // With only the TS tier present this file would prove nothing: TS was
    // already correct, and it is the four NATIVE tiers that were wrong.
    expect(tiers.map(t => t.name).length).toBeGreaterThanOrEqual(5);
  });

  it('every available tier accepts the bare spelling', () => {
    const rejected: string[] = [];
    for (const tier of tiers) {
      try {
        tier.run(barePath);
      } catch (e) {
        rejected.push(`${tier.name}: ${(e as Error).message.split('\n')[0]}`);
      }
    }
    expect(rejected).toEqual([]);
  });

  it('every available tier emits the same script for the bare spelling', () => {
    const byTier = Object.fromEntries(tiers.map(t => [t.name, t.run(barePath)]));
    expect(new Set(Object.values(byTier)).size,
      `tiers disagree: ${JSON.stringify(byTier, null, 2)}`).toBe(1);
  });

  it('the bare and this.-qualified spellings are the same program', () => {
    // If they diverged, one of the two would be resolving to something other
    // than the property — and the parity above could hold while both are wrong.
    for (const tier of tiers) {
      expect(tier.run(barePath), `${tier.name} disagrees with itself across spellings`)
        .toBe(tier.run(qualifiedPath));
    }
  });
});
