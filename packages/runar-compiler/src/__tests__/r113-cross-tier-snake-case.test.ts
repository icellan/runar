import { describe, it, expect } from 'vitest';
import { execFileSync, execSync } from 'child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'fs';
import { createHash } from 'crypto';
import { tmpdir } from 'os';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { compile } from '../index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = join(__dirname, '..', '..', '..', '..');

/**
 * R-113 (second pass) — the snake_case → camelCase convergence missed three
 * `.runar.rb` parsers and one `.runar.move` parser.
 *
 * The first R-113 sweep put `snakeToCamelCore` (split on `_`, capitalise the
 * first character of every following part) behind the TypeScript parsers and
 * declared the seven tiers converged. Four hand-rolled copies survived it,
 * all implementing the OLD rule — uppercase only a lower-case letter or a
 * digit after the underscore, leave `_` before a capital in place:
 *
 *   compilers/ruby/lib/runar_compiler/frontend/parser_ruby.rb  (regex)
 *   compilers/python/runar_compiler/frontend/parser_ruby.py    (regex)
 *   compilers/java/.../frontend/RbParser.java                  (character loop,
 *       same rule with no regex — invisible to a grep for the pattern)
 *   compilers/ruby/lib/runar_compiler/frontend/parser_move.rb  (regex)
 *
 * Measured, before the fix, on the two sources below:
 *
 *   .runar.rb    ts go rust zig   totalA     python ruby java   total_A
 *   .runar.move  ts go rust zig python java  totalA     ruby    total_A
 *
 * WHY NO EXISTING TEST CAUGHT IT. The divergence is in the artifact's
 * `stateFields[].name` only — the emitted script is byte-identical either
 * way (measured: all seven tiers emit the same 715-byte script for both
 * sources, before and after). Hex parity, the conformance suite's main
 * instrument, is structurally blind to it. It bites at the SDK boundary:
 * `serializeState` (packages/runar-sdk/src/state.ts) looks state up by
 * `values[field.name]`, so a state object keyed by one tier's name against
 * another tier's artifact misses the lookup entirely.
 *
 * The identifiers below pin all three boundaries the rules disagree about —
 * `_` before an upper-case letter (the divergent one), `_` before a
 * lower-case letter, and `_` before a digit — so a fix cannot over-correct
 * (renaming `total_b`/`total_1`) or under-correct (leaving `total_A`).
 */

const EXPECTED_NAMES = ['totalA', 'totalB', 'total1'];

const RB_SOURCE = `require 'runar'

class Totals < Runar::StatefulSmartContract
  prop :total_A, Bigint
  prop :total_b, Bigint
  prop :total_1, Bigint

  def initialize(total_A, total_b, total_1)
    super(total_A, total_b, total_1)
    @total_A = total_A
    @total_b = total_b
    @total_1 = total_1
  end

  runar_public
  def bump
    @total_A += 1
    @total_b += 1
    @total_1 += 1
  end
end
`;

const MOVE_SOURCE = `module Totals {
    resource struct Totals {
        total_A: &mut bigint,
        total_b: &mut bigint,
        total_1: &mut bigint,
    }

    public fun bump(contract: &mut Totals) {
        contract.total_A = contract.total_A + 1;
        contract.total_b = contract.total_b + 1;
        contract.total_1 = contract.total_1 + 1;
    }
}
`;

// ---------------------------------------------------------------------------
// Toolchain discovery. Mirrors cross-compiler.test.ts: warn-and-skip locally
// so a dev without all seven toolchains can still iterate; hard-fail when
// RUNAR_REQUIRE_ALL_COMPILERS=1 says the job's contract IS "all 7 present".
// ---------------------------------------------------------------------------

const REQUIRE_ALL = process.env.RUNAR_REQUIRE_ALL_COMPILERS === '1';

function probe(cmd: string, opts: { cwd?: string } = {}): boolean {
  try {
    execSync(cmd, { stdio: 'pipe', cwd: opts.cwd });
    return true;
  } catch {
    return false;
  }
}

const GO_DIR = join(REPO_ROOT, 'compilers', 'go');
const RUST_DIR = join(REPO_ROOT, 'compilers', 'rust');
const PYTHON_DIR = join(REPO_ROOT, 'compilers', 'python');
const ZIG_DIR = join(REPO_ROOT, 'compilers', 'zig');
const RUBY_DIR = join(REPO_ROOT, 'compilers', 'ruby');
const JAVA_DIR = join(REPO_ROOT, 'compilers', 'java');

const goBinary = existsSync(join(GO_DIR, 'runar-go')) ? join(GO_DIR, 'runar-go') : null;
const rustBinary = existsSync(join(RUST_DIR, 'target', 'release', 'runar-compiler-rust'))
  ? join(RUST_DIR, 'target', 'release', 'runar-compiler-rust')
  : null;
const zigBinary = existsSync(join(ZIG_DIR, 'zig-out', 'bin', 'runar-zig'))
  ? join(ZIG_DIR, 'zig-out', 'bin', 'runar-zig')
  : null;
const rubyScript = existsSync(join(RUBY_DIR, 'bin', 'runar-compiler-ruby')) && probe('ruby --version')
  ? join(RUBY_DIR, 'bin', 'runar-compiler-ruby')
  : null;
const hasPython = probe('python3 --version') && probe('python3 -c "import runar_compiler"', { cwd: PYTHON_DIR });

function findJavaJar(): string | null {
  if (!probe('java -version')) return null;
  const libsDir = join(JAVA_DIR, 'build', 'libs');
  if (!existsSync(libsDir)) return null;
  const preferred = join(libsDir, 'runar-java.jar');
  if (existsSync(preferred)) return preferred;
  for (const entry of readdirSync(libsDir)) {
    if (entry.startsWith('runar-java-compiler-') && entry.endsWith('.jar')) {
      return join(libsDir, entry);
    }
  }
  return null;
}
const javaJar = findJavaJar();

// ---------------------------------------------------------------------------
// One tier, one source → (stateField names, script hex).
// ---------------------------------------------------------------------------

interface TierResult {
  names: string[];
  script: string;
}

function run(cmd: string, args: string[], cwd: string): string {
  return execFileSync(cmd, args, {
    cwd,
    encoding: 'utf-8',
    maxBuffer: 256 * 1024 * 1024,
    timeout: 300_000,
  });
}

function fromArtifactJson(json: string): TierResult {
  const artifact = JSON.parse(json) as {
    stateFields?: Array<{ name: string }>;
    script: string;
  };
  return { names: (artifact.stateFields ?? []).map((f) => f.name), script: artifact.script };
}

/** Every tier that is available on this machine, as name → compile function. */
function availableTiers(): Record<string, (sourcePath: string) => TierResult> {
  const tiers: Record<string, (sourcePath: string) => TierResult> = {
    ts: (sourcePath) => {
      const r = compile(readFileSync(sourcePath, 'utf-8'), { fileName: sourcePath });
      if (!r.success) {
        throw new Error(`ts compile failed: ${r.diagnostics.map((d) => d.message).join(' | ')}`);
      }
      const artifact = r.artifact!;
      return {
        names: (artifact.stateFields ?? []).map((f) => f.name),
        script: artifact.script,
      };
    },
  };

  if (goBinary) {
    tiers.go = (p) => fromArtifactJson(run(goBinary, ['--source', p], GO_DIR));
  }
  if (rustBinary) {
    tiers.rust = (p) => fromArtifactJson(run(rustBinary, ['--source', p], RUST_DIR));
  }
  if (hasPython) {
    tiers.python = (p) =>
      fromArtifactJson(run('python3', ['-m', 'runar_compiler', '--source', p], PYTHON_DIR));
  }
  if (zigBinary) {
    tiers.zig = (p) => fromArtifactJson(run(zigBinary, ['--source', p], ZIG_DIR));
  }
  if (rubyScript) {
    tiers.ruby = (p) => fromArtifactJson(run('ruby', [rubyScript, '--source', p], RUBY_DIR));
  }
  if (javaJar) {
    // The Java CLI prints ANF IR on stdout by default; the deployable
    // artifact (the thing that carries stateFields) only comes out of
    // --emit-artifact.
    tiers.java = (p) => {
      const out = join(mkdtempSync(join(tmpdir(), 'r113-java-')), 'artifact.json');
      try {
        run('java', ['-jar', javaJar, '--source', p, '--emit-artifact', out], JAVA_DIR);
        return fromArtifactJson(readFileSync(out, 'utf-8'));
      } finally {
        rmSync(dirname(out), { recursive: true, force: true });
      }
    };
  }
  return tiers;
}

const TIERS = availableTiers();
const MISSING = ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'].filter((t) => !(t in TIERS));

function compileAllTiers(fileName: string, source: string): Record<string, TierResult> {
  const dir = mkdtempSync(join(tmpdir(), 'r113-'));
  const sourcePath = join(dir, fileName);
  writeFileSync(sourcePath, source, 'utf-8');
  try {
    const out: Record<string, TierResult> = {};
    for (const [tier, fn] of Object.entries(TIERS)) {
      out[tier] = fn(sourcePath);
    }
    return out;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('R-113 snake_case normalisation is identical in all seven tiers', () => {
  it('every tier is available (or the job did not ask for all seven)', () => {
    if (MISSING.length > 0) {
      const msg = `tiers not available locally: ${MISSING.join(', ')}`;
      if (REQUIRE_ALL) throw new Error(msg);
      console.warn(`WARNING: ${msg} — their assertions below are skipped`);
    }
    expect(Object.keys(TIERS).length).toBeGreaterThan(1);
  });

  it('.runar.rb: total_A / total_b / total_1 normalise the same way everywhere', () => {
    const results = compileAllTiers('Totals.runar.rb', RB_SOURCE);
    const byTier = Object.fromEntries(
      Object.entries(results).map(([tier, r]) => [tier, r.names]),
    );
    // Reported as a whole map so a failure names every divergent tier at once.
    expect(byTier).toEqual(
      Object.fromEntries(Object.keys(results).map((tier) => [tier, EXPECTED_NAMES])),
    );
  });

  it('.runar.move: same three shapes, same answer in every tier', () => {
    const results = compileAllTiers('Totals.runar.move', MOVE_SOURCE);
    const byTier = Object.fromEntries(
      Object.entries(results).map(([tier, r]) => [tier, r.names]),
    );
    expect(byTier).toEqual(
      Object.fromEntries(Object.keys(results).map((tier) => [tier, EXPECTED_NAMES])),
    );
  });

  it('the script hex is identical across tiers AND across the two surfaces', () => {
    // Pinned so the next reader can see why hex parity never caught this: the
    // name divergence moves no script byte at all. If this assertion ever
    // fails the fix has changed codegen, which it must not.
    const rb = compileAllTiers('Totals.runar.rb', RB_SOURCE);
    const move = compileAllTiers('Totals.runar.move', MOVE_SOURCE);
    const shas = new Set<string>();
    for (const r of [...Object.values(rb), ...Object.values(move)]) {
      shas.add(createHash('sha256').update(Buffer.from(r.script, 'hex')).digest('hex'));
    }
    expect([...shas]).toHaveLength(1);
  });
});
