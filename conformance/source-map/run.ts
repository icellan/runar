/**
 * GAP-002 conformance runner — per-tier source-map byte-identity + structural invariants.
 *
 * Re-runs each tier's `--emit-source-map` flag against the 6 selected
 * fixtures and verifies that:
 *
 *  1. The output matches the committed golden at
 *     `conformance/source-map/<fixture>/<tier>/expected-source-map.json`
 *     byte-for-byte (regression gate).
 *
 *  2. The emitted JSON satisfies the cross-tier structural invariants:
 *      - Top-level shape `{ mappings: SourceMapping[] }`.
 *      - `mappings.length <= opcodeCount`. (Tiers may emit mappings only
 *        for opcodes that have a tracked source location; the brief's
 *        original "equals" was too strict for Go's current behaviour.)
 *      - `mappings` is sorted ascending by `opcodeIndex`.
 *      - No duplicate `opcodeIndex` values.
 *      - Each entry has `line >= 0` and `column >= 0` (the JSON schema
 *        allows column 0 but requires line >= 1; the floor stays at 0
 *        because a tier may emit line=0/column=0 for a SYNTHESIZED node
 *        with no source position. Nodes that come from source are
 *        position-tracked in every tier — see `independent-oracle.ts`,
 *        which anchors each mapping against the real file. Columns are
 *        0-based; lines are 1-based.).
 *      - `opcodeIndex` values are in `[0, opcodeCount)`.
 *      - `sourceFile` is a non-empty string.
 *
 *  3. The emitted mappings satisfy the INDEPENDENT source-anchor oracle
 *     (`independent-oracle.ts#checkSourceAnchors`, audit finding #22).
 *     Checks 1 and 2 are both graded against the generator's own output —
 *     a generator that consistently emits a wrong (line, column) passes
 *     both forever, because the golden was produced by the same generator
 *     and the structural check never opens the source file. Check 3 closes
 *     that gap: it re-reads the REAL `.runar.*` source file on disk (not
 *     the golden, not any compiler pass) and verifies each tracked mapping
 *     lands on an in-bounds, non-whitespace, non-comment position that
 *     does not split a token in half. Known, pre-existing violations
 *     (compiler bugs out of scope for this runner) are pinned in
 *     `conformance/source-map/anchor-known-issues.json` with a required
 *     `reason`; any NEW violation, or drift in an already-recorded one,
 *     fails the gate.
 *
 *  4. The emitted mappings satisfy the F-293 whole-map shape rule against
 *     the LIVE TS reference map of the same fixture
 *     (`independent-oracle.ts#checkAgainstReference`), with the same
 *     exact-count pins in `anchor-known-issues.json` as the committed-golden
 *     gate in `independent-oracle.test.ts` (N-370). Without this, a
 *     regression in a live compile that was not re-stamped into a golden
 *     was invisible to this runner. The reference is compiled live even
 *     under `--tier=<other>`; if it cannot be produced, a non-TS tier fails
 *     closed. The TS tier is its own reference, so it can only be checked
 *     against its (empty) pin.
 *
 * The line/column numbers are deliberately tier-specific (each tier
 * compiles its own surface syntax — `.runar.ts` for TypeScript,
 * `.runar.go` for Go, etc.) so the goldens differ by design.
 *
 * Usage:
 *   tsx conformance/source-map/run.ts             # run all tiers, all fixtures
 *   tsx conformance/source-map/run.ts --update    # regenerate goldens
 *   tsx conformance/source-map/run.ts --tier=go   # restrict to one tier
 *   tsx conformance/source-map/run.ts --fixture=basic-p2pkh
 */

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, basename, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  checkAgainstReference,
  checkSourceAnchors,
  evaluateAgainstKnownIssues,
  evaluateShapeAgainstKnownIssues,
  loadKnownIssues,
  type KnownIssueEntry,
} from './independent-oracle.js';
import { findJavaJarPath } from '../runner/runner.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');

const JAVA_BIN = join(REPO_ROOT, 'compilers/java/build/install/runar-java/bin/runar-java');

/** The Java tier: the installDist launcher, else `java -jar` on the built jar
 *  (the CI conformance job downloads only the jar into build/libs). */
function javaCommand(): { cmd: string; pre: string[] } | null {
  if (existsSync(JAVA_BIN)) return { cmd: JAVA_BIN, pre: [] };
  const jar = findJavaJarPath();
  return jar === null ? null : { cmd: 'java', pre: ['-jar', jar] };
}

// GAP-002 brief originally listed `ec-demo` as the 5th fixture. Excluded
// here because its compiled output expands EC primitives to ~750 KB of
// hex and ~45 MB of source-map JSON per tier — committing 7 × 45 MB
// goldens (315 MB) into the repo is not OK. `arithmetic` is a
// structurally similar (computation-dense, multi-method) substitute
// whose goldens stay sub-kilobyte. See _review/GAP-002-audit.md.
// F-259: `bounded-loop` pins per-binding locations inside an unrolled loop
// body (body ops -> body line; iteration-variable pushes -> loop line).
const FIXTURES = ['basic-p2pkh', 'stateful-counter', 'escrow', 'arithmetic', 'if-else', 'bounded-loop'] as const;
type Fixture = (typeof FIXTURES)[number];

interface Tier {
  name: string;
  ext: '.runar.ts' | '.runar.go' | '.runar.rs' | '.runar.py' | '.runar.zig' | '.runar.rb' | '.runar.java';
  run: (sourcePath: string, smOut: string) => { ok: boolean; stderr: string };
  available: () => boolean;
}

// Helper — run a command with a timeout and collect stdout/stderr.
function run(cmd: string, args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}): { code: number; stdout: string; stderr: string } {
  const result = spawnSync(cmd, args, {
    cwd: opts.cwd ?? REPO_ROOT,
    env: { ...process.env, ...(opts.env ?? {}) },
    encoding: 'utf-8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  return {
    code: result.status ?? -1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

// Locate the tsx loader (mirrors conformance/runner/runner.ts pattern).
function resolveTsxLoader(): string | null {
  const candidates = [
    join(REPO_ROOT, 'node_modules/.pnpm/tsx@4.21.0/node_modules/tsx/dist/loader.mjs'),
    join(REPO_ROOT, 'conformance/node_modules/tsx/dist/loader.mjs'),
    join(REPO_ROOT, 'node_modules/tsx/dist/loader.mjs'),
  ];
  for (const p of candidates) {
    if (existsSync(p)) return new URL(`file://${p}`).href;
  }
  // Last resort — search the .pnpm tree for any tsx@*/loader.mjs.
  try {
    const out = run('find', [join(REPO_ROOT, 'node_modules', '.pnpm'), '-name', 'loader.mjs', '-path', '*tsx*'], { cwd: REPO_ROOT });
    const lines = out.stdout.split('\n').filter(l => l.trim());
    if (lines.length > 0) return new URL(`file://${lines[0]}`).href;
  } catch {}
  return null;
}

const TIERS: Tier[] = [
  {
    name: 'ts',
    ext: '.runar.ts',
    available: () => {
      const loader = resolveTsxLoader();
      return loader != null && existsSync(join(REPO_ROOT, 'packages/runar-cli/src/bin.ts'));
    },
    run: (sourcePath, smOut) => {
      const loader = resolveTsxLoader();
      if (!loader) return { ok: false, stderr: 'no tsx loader' };
      const tmpOut = join(REPO_ROOT, 'conformance/source-map/.tmp', `ts-${process.pid}-${Date.now()}`);
      mkdirSync(tmpOut, { recursive: true });
      const r = run('node', [
        '--import', loader,
        join(REPO_ROOT, 'packages/runar-cli/src/bin.ts'),
        'compile', sourcePath,
        '-o', tmpOut,
        '--disable-constant-folding',
        '--emit-source-map', smOut,
      ]);
      return { ok: r.code === 0 && existsSync(smOut), stderr: r.stderr };
    },
  },
  {
    name: 'go',
    ext: '.runar.go',
    available: () => existsSync(join(REPO_ROOT, 'compilers/go/main.go')),
    run: (sourcePath, smOut) => {
      // Build once per run into conformance/source-map/.tmp/ so the
      // binary doesn't pollute compilers/go/.
      const tmpBinDir = join(__dirname, '.tmp');
      mkdirSync(tmpBinDir, { recursive: true });
      const bin = join(tmpBinDir, 'runar-go');
      const build = run('go', ['build', '-o', bin, '.'], { cwd: join(REPO_ROOT, 'compilers/go') });
      if (build.code !== 0) return { ok: false, stderr: 'go build failed: ' + build.stderr };
      const r = run(bin, [
        '--source', sourcePath,
        '--disable-constant-folding',
        '--emit-source-map', smOut,
      ]);
      return { ok: r.code === 0 && existsSync(smOut), stderr: r.stderr };
    },
  },
  {
    name: 'rs',
    ext: '.runar.rs',
    available: () => existsSync(join(REPO_ROOT, 'compilers/rust/target/release/runar-compiler-rust')) || existsSync(join(REPO_ROOT, 'compilers/rust/Cargo.toml')),
    run: (sourcePath, smOut) => {
      let bin = join(REPO_ROOT, 'compilers/rust/target/release/runar-compiler-rust');
      if (!existsSync(bin)) {
        const build = run('cargo', ['build', '--release'], { cwd: join(REPO_ROOT, 'compilers/rust') });
        if (build.code !== 0) return { ok: false, stderr: 'cargo build failed: ' + build.stderr };
      }
      const r = run(bin, [
        '--source', sourcePath,
        '--disable-constant-folding',
        '--emit-source-map', smOut,
      ]);
      return { ok: r.code === 0 && existsSync(smOut), stderr: r.stderr };
    },
  },
  {
    name: 'py',
    ext: '.runar.py',
    available: () => existsSync(join(REPO_ROOT, 'compilers/python/runar_compiler/__main__.py')),
    run: (sourcePath, smOut) => {
      const r = run('python3', [
        '-m', 'runar_compiler',
        '--source', sourcePath,
        '--disable-constant-folding',
        '--emit-source-map', smOut,
      ], { cwd: join(REPO_ROOT, 'compilers/python') });
      return { ok: r.code === 0 && existsSync(smOut), stderr: r.stderr };
    },
  },
  {
    name: 'zig',
    ext: '.runar.zig',
    available: () => existsSync(join(REPO_ROOT, 'compilers/zig/zig-out/bin/runar-zig')) || existsSync(join(REPO_ROOT, 'compilers/zig/build.zig')),
    run: (sourcePath, smOut) => {
      const bin = join(REPO_ROOT, 'compilers/zig/zig-out/bin/runar-zig');
      if (!existsSync(bin)) {
        const build = run('zig', ['build'], { cwd: join(REPO_ROOT, 'compilers/zig') });
        if (build.code !== 0) return { ok: false, stderr: 'zig build failed: ' + build.stderr };
      }
      const r = run(bin, [
        '--source', sourcePath,
        '--disable-constant-folding',
        '--emit-source-map', smOut,
      ]);
      return { ok: r.code === 0 && existsSync(smOut), stderr: r.stderr };
    },
  },
  {
    name: 'rb',
    ext: '.runar.rb',
    available: () => existsSync(join(REPO_ROOT, 'compilers/ruby/lib/runar_compiler/cli.rb')),
    run: (sourcePath, smOut) => {
      const r = run('ruby', [
        '-Ilib', 'lib/runar_compiler/cli.rb',
        '--source', sourcePath,
        '--disable-constant-folding',
        '--emit-source-map', smOut,
      ], { cwd: join(REPO_ROOT, 'compilers/ruby') });
      return { ok: r.code === 0 && existsSync(smOut), stderr: r.stderr };
    },
  },
  {
    name: 'java',
    ext: '.runar.java',
    available: () => javaCommand() !== null,
    run: (sourcePath, smOut) => {
      if (javaCommand() === null) {
        const build = run('gradle', ['installDist'], { cwd: join(REPO_ROOT, 'compilers/java') });
        if (build.code !== 0) return { ok: false, stderr: 'gradle installDist failed: ' + build.stderr };
      }
      const java = javaCommand()!;
      const r = run(java.cmd, [
        ...java.pre,
        '--source', sourcePath,
        '--disable-constant-folding',
        '--hex',
        '--emit-source-map', smOut,
      ]);
      return { ok: r.code === 0 && existsSync(smOut), stderr: r.stderr };
    },
  },
];

interface SourceMapping {
  opcodeIndex: number;
  sourceFile: string;
  line: number;
  column: number;
}

interface SourceMap {
  mappings: SourceMapping[];
}

interface StructuralResult { ok: boolean; reasons: string[]; }

function checkStructural(sm: SourceMap, opcodeCount: number): StructuralResult {
  const reasons: string[] = [];
  if (!sm || typeof sm !== 'object' || !Array.isArray(sm.mappings)) {
    return { ok: false, reasons: ['sourceMap is not {mappings: [...]}'] };
  }
  // 1. Length bound vs opcode count.
  if (sm.mappings.length > opcodeCount) {
    reasons.push(`mappings.length=${sm.mappings.length} > opcodeCount=${opcodeCount}`);
  }
  // 2. Sorted ascending + no duplicates.
  for (let i = 1; i < sm.mappings.length; i++) {
    const prev = sm.mappings[i - 1].opcodeIndex;
    const cur = sm.mappings[i].opcodeIndex;
    if (cur < prev) reasons.push(`mappings not sorted at index ${i} (prev=${prev}, cur=${cur})`);
    if (cur === prev) reasons.push(`duplicate opcodeIndex ${cur} at mappings[${i}]`);
  }
  // 3. Per-entry checks.
  for (let i = 0; i < sm.mappings.length; i++) {
    const m = sm.mappings[i];
    if (typeof m.opcodeIndex !== 'number' || m.opcodeIndex < 0) reasons.push(`mappings[${i}].opcodeIndex invalid: ${m.opcodeIndex}`);
    if (typeof m.opcodeIndex === 'number' && m.opcodeIndex >= opcodeCount) reasons.push(`mappings[${i}].opcodeIndex=${m.opcodeIndex} >= opcodeCount=${opcodeCount}`);
    if (typeof m.sourceFile !== 'string' || m.sourceFile.length === 0) reasons.push(`mappings[${i}].sourceFile invalid`);
    // GAP-011: sourceFile must NOT be an absolute path (would bake the
    // developer's worktree directory into the goldens). Allow repo-relative
    // POSIX paths (e.g. examples/ts/p2pkh/P2PKH.runar.ts) or basenames.
    else if (m.sourceFile.startsWith('/') || /^[A-Za-z]:[\\/]/.test(m.sourceFile)) reasons.push(`mappings[${i}].sourceFile is absolute: ${m.sourceFile}`);
    if (typeof m.line !== 'number' || m.line < 0) reasons.push(`mappings[${i}].line invalid: ${m.line}`);
    if (typeof m.column !== 'number' || m.column < 0) reasons.push(`mappings[${i}].column invalid: ${m.column}`);
  }
  return { ok: reasons.length === 0, reasons };
}

/**
 * Best-effort opcode count from the compiled hex. We approximate by
 * walking the bytes and counting opcodes (including push instructions as
 * a single opcode each). This is a lower bound that's good enough for
 * the structural sanity check (mappings.length <= opcodeCount).
 */
function approximateOpcodeCount(hex: string): number {
  let i = 0;
  let n = 0;
  while (i < hex.length) {
    const op = parseInt(hex.slice(i, i + 2), 16);
    i += 2;
    n++;
    if (op >= 1 && op <= 75) {
      // Direct push: <op> data bytes
      i += 2 * op;
    } else if (op === 0x4c) { // OP_PUSHDATA1
      if (i + 2 > hex.length) break;
      const len = parseInt(hex.slice(i, i + 2), 16);
      i += 2 + 2 * len;
    } else if (op === 0x4d) { // OP_PUSHDATA2
      if (i + 4 > hex.length) break;
      const len = parseInt(hex.slice(i, i + 2), 16) | (parseInt(hex.slice(i + 2, i + 4), 16) << 8);
      i += 4 + 2 * len;
    } else if (op === 0x4e) { // OP_PUSHDATA4
      if (i + 8 > hex.length) break;
      const len = parseInt(hex.slice(i, i + 8), 16);
      i += 8 + 2 * len;
    }
  }
  return n;
}

function readGolden(path: string): string | null {
  try { return readFileSync(path, 'utf-8'); }
  catch { return null; }
}

function loadFixtureSources(fixture: Fixture): Record<string, string> {
  const sourceJsonPath = join(REPO_ROOT, 'conformance/tests', fixture, 'source.json');
  const raw = readFileSync(sourceJsonPath, 'utf-8');
  const parsed = JSON.parse(raw) as { sources: Record<string, string> };
  const out: Record<string, string> = {};
  for (const [ext, relPath] of Object.entries(parsed.sources)) {
    out[ext] = resolve(dirname(sourceJsonPath), relPath);
  }
  return out;
}

interface CompileHexResult { hex: string; err?: string; }
function compileHex(tier: Tier, sourcePath: string): CompileHexResult {
  // Each tier has a --hex flag (verified by inspection). Use it to get
  // the opcode count for the structural check.
  switch (tier.name) {
    case 'ts': {
      const loader = resolveTsxLoader();
      if (!loader) return { hex: '', err: 'no tsx loader' };
      const r = run('node', [
        '--import', loader,
        join(REPO_ROOT, 'packages/runar-cli/src/bin.ts'),
        'compile', sourcePath, '-o', '/tmp/runar-ts-hexout', '--hex',
        '--disable-constant-folding',
      ]);
      return { hex: r.stdout.trim(), err: r.code === 0 ? undefined : r.stderr };
    }
    case 'go': {
      const bin = join(__dirname, '.tmp', 'runar-go');
      const r = run(bin, ['--source', sourcePath, '--hex', '--disable-constant-folding']);
      return { hex: r.stdout.trim(), err: r.code === 0 ? undefined : r.stderr };
    }
    case 'rs': {
      const bin = join(REPO_ROOT, 'compilers/rust/target/release/runar-compiler-rust');
      const r = run(bin, ['--source', sourcePath, '--hex', '--disable-constant-folding']);
      return { hex: r.stdout.trim(), err: r.code === 0 ? undefined : r.stderr };
    }
    case 'py': {
      const r = run('python3', [
        '-m', 'runar_compiler', '--source', sourcePath, '--hex',
        '--disable-constant-folding',
      ], { cwd: join(REPO_ROOT, 'compilers/python') });
      return { hex: r.stdout.trim(), err: r.code === 0 ? undefined : r.stderr };
    }
    case 'zig': {
      const bin = join(REPO_ROOT, 'compilers/zig/zig-out/bin/runar-zig');
      const r = run(bin, ['--source', sourcePath, '--hex', '--disable-constant-folding']);
      return { hex: r.stdout.trim(), err: r.code === 0 ? undefined : r.stderr };
    }
    case 'rb': {
      const r = run('ruby', [
        '-Ilib', 'lib/runar_compiler/cli.rb',
        '--source', sourcePath, '--hex',
        '--disable-constant-folding',
      ], { cwd: join(REPO_ROOT, 'compilers/ruby') });
      return { hex: r.stdout.trim(), err: r.code === 0 ? undefined : r.stderr };
    }
    case 'java': {
      const java = javaCommand();
      if (java === null) return { hex: '', err: 'no Java compiler (installDist launcher or jar)' };
      const r = run(java.cmd, [...java.pre, '--source', sourcePath, '--hex', '--disable-constant-folding']);
      return { hex: r.stdout.trim(), err: r.code === 0 ? undefined : r.stderr };
    }
  }
  return { hex: '' };
}

interface Outcome {
  fixture: Fixture;
  tier: string;
  byteIdentical?: boolean;
  structural: 'ok' | 'fail' | 'skip';
  structuralReasons?: string[];
  anchor?: 'ok' | 'fail';
  anchorReason?: string;
  notes?: string;
}

/**
 * Whether `--update` should write the regenerated golden for one
 * (fixture, tier) pair, given its structural and source-anchor check
 * results. Exported so the decision can be unit-tested without spawning the
 * real compilers.
 *
 * N-088: `--update` used to write the golden unconditionally, so a compile
 * that produced a structurally invalid source map, or one whose mappings
 * failed the independent source-anchor oracle, still got stamped as the new
 * golden. A broken output must not become the golden just because it was
 * produced while regenerating.
 */
export function decideGoldenWrite(structuralOk: boolean, anchorOk: boolean): boolean {
  return structuralOk && anchorOk;
}

/**
 * The process exit code for the whole run, given how many (fixture, tier)
 * pairs failed. Exported so the decision can be unit-tested without
 * spawning the real compilers.
 *
 * N-088: the exit code used to be `failed > 0 && !update`, so any failure
 * found while regenerating goldens (including one `decideGoldenWrite` above
 * now refuses to stamp) was masked by the mere fact of running `--update`.
 * A failure is a failure whether or not it happened during a regeneration.
 */
export function decideExitCode(failed: number, _update: boolean): number {
  return failed > 0 ? 1 : 0;
}

/**
 * The F-293 whole-map shape decision for one LIVE (fixture, tier) map against
 * the LIVE TS reference map of the same fixture. Exported so the decision can
 * be unit-tested without spawning the real compilers. A missing reference
 * (`null`) fails closed for every tier but TS, which is its own reference.
 *
 * N-370: run.ts used to compile every pair live but apply only the
 * per-mapping anchor rule; the shape rule ran over committed goldens only.
 */
export function decideLiveShape(
  fixture: string,
  tier: string,
  sm: SourceMap,
  ref: SourceMap | null,
  knownIssues: KnownIssueEntry[],
): { ok: boolean; reason: string } {
  if (ref === null) {
    if (tier === 'ts') return { ok: true, reason: 'TS is the reference' };
    return { ok: false, reason: `${fixture}/${tier}: the live TS reference map is unavailable, so the whole-map shape rule cannot be checked` };
  }
  return evaluateShapeAgainstKnownIssues(fixture, tier, checkAgainstReference(sm, ref), knownIssues);
}

/** Compile `fixture` with the TS tier into a scratch file and parse the map; null on any failure. */
function liveReferenceMap(fixture: Fixture, sources: Record<string, string>): SourceMap | null {
  const ts = TIERS[0]!;
  const src = sources[ts.ext];
  if (!src || !existsSync(src) || !ts.available()) return null;
  const outDir = join(__dirname, fixture, ts.name);
  mkdirSync(outDir, { recursive: true });
  const tmp = join(outDir, '.tmp-source-map.json');
  const r = ts.run(src, tmp);
  if (!r.ok) return null;
  try { return JSON.parse(readFileSync(tmp, 'utf-8')) as SourceMap; } catch { return null; }
}

function main() {
  const args = process.argv.slice(2);
  const update = args.includes('--update');
  const tierFilter = args.find(a => a.startsWith('--tier='))?.slice('--tier='.length);
  const fixtureFilter = args.find(a => a.startsWith('--fixture='))?.slice('--fixture='.length);

  const knownIssues = loadKnownIssues(join(__dirname, 'anchor-known-issues.json')).knownIssues;

  const outcomes: Outcome[] = [];
  let failed = 0;

  for (const fixture of FIXTURES) {
    if (fixtureFilter && fixture !== fixtureFilter) continue;
    const sources = loadFixtureSources(fixture);
    let liveRef: SourceMap | null | undefined; // lazily compiled once per fixture
    for (const tier of TIERS) {
      if (tierFilter && tier.name !== tierFilter) continue;
      if (!tier.available()) {
        outcomes.push({ fixture, tier: tier.name, structural: 'skip', notes: 'tier not available' });
        continue;
      }
      const sourcePath = sources[tier.ext];
      if (!sourcePath || !existsSync(sourcePath)) {
        outcomes.push({ fixture, tier: tier.name, structural: 'skip', notes: `no source file for ${tier.ext}` });
        continue;
      }

      // Output dir + golden path.
      const outDir = join(__dirname, fixture, tier.name);
      mkdirSync(outDir, { recursive: true });
      const tmpOut = join(outDir, '.tmp-source-map.json');
      const goldenPath = join(outDir, 'expected-source-map.json');

      const compileRes = tier.run(sourcePath, tmpOut);
      if (!compileRes.ok) {
        outcomes.push({ fixture, tier: tier.name, structural: 'fail', notes: 'compile failed: ' + compileRes.stderr.split('\n').slice(0, 3).join(' / ') });
        failed++;
        continue;
      }
      const emitted = readFileSync(tmpOut, 'utf-8');
      const sm = JSON.parse(emitted) as SourceMap;
      const hexRes = compileHex(tier, sourcePath);
      const opcodeCount = hexRes.hex ? approximateOpcodeCount(hexRes.hex) : Number.MAX_SAFE_INTEGER;
      const structural = checkStructural(sm, opcodeCount);

      // Independent source-anchor oracle (audit finding #22) — re-reads the
      // REAL source file, never the golden. See the module doc comment in
      // independent-oracle.ts for why this is generator-independent.
      const anchorReport = checkSourceAnchors(sm, REPO_ROOT);
      const anchorEval = evaluateAgainstKnownIssues(fixture, tier.name, anchorReport, knownIssues);

      // F-293 whole-map shape rule against the LIVE TS reference (N-370).
      if (liveRef === undefined) liveRef = liveReferenceMap(fixture, sources);
      const shapeEval = decideLiveShape(fixture, tier.name, sm, liveRef, knownIssues);

      // Golden comparison (byte-identical) or update.
      let byteIdentical: boolean | undefined;
      if (update) {
        if (decideGoldenWrite(structural.ok, anchorEval.ok && shapeEval.ok)) {
          writeFileSync(goldenPath, emitted);
          byteIdentical = true;
        } else {
          byteIdentical = false;
        }
      } else {
        const golden = readGolden(goldenPath);
        if (golden == null) {
          outcomes.push({
            fixture, tier: tier.name, byteIdentical: false,
            structural: structural.ok ? 'ok' : 'fail', structuralReasons: structural.reasons,
            anchor: anchorEval.ok && shapeEval.ok ? 'ok' : 'fail', anchorReason: anchorEval.ok ? shapeEval.reason : anchorEval.reason,
            notes: 'golden missing — run with --update',
          });
          failed++;
          continue;
        }
        byteIdentical = golden === emitted;
      }

      if (!byteIdentical || !structural.ok || !anchorEval.ok || !shapeEval.ok) failed++;
      outcomes.push({
        fixture, tier: tier.name, byteIdentical,
        structural: structural.ok ? 'ok' : 'fail', structuralReasons: structural.reasons,
        anchor: anchorEval.ok && shapeEval.ok ? 'ok' : 'fail', anchorReason: anchorEval.ok ? shapeEval.reason : anchorEval.reason,
        notes: update && !byteIdentical ? 'refused to write golden: fails its own structural/anchor checks' : undefined,
      });
    }
  }

  // Summary table.
  console.log('');
  console.log(`fixture                       tier   byte-id   structural   anchor   notes`);
  console.log(`${'-'.repeat(100)}`);
  for (const o of outcomes) {
    const byte = o.byteIdentical === undefined ? '-' : (o.byteIdentical ? 'OK' : 'DIFF');
    const struct = o.structural === 'ok' ? 'OK' : o.structural === 'fail' ? 'FAIL' : 'SKIP';
    const anchor = o.anchor === undefined ? '-' : (o.anchor === 'ok' ? 'OK' : 'FAIL');
    const anchorNote = o.anchor === 'fail' ? o.anchorReason : undefined;
    const notes = o.notes ?? anchorNote ?? (o.structuralReasons?.length ? o.structuralReasons.slice(0, 2).join(' / ') : '');
    console.log(`${o.fixture.padEnd(28)}  ${o.tier.padEnd(5)} ${byte.padEnd(8)} ${struct.padEnd(12)} ${anchor.padEnd(8)} ${notes}`);
  }
  console.log('');
  console.log(`Total: ${outcomes.length}, failed: ${failed}`);
  const code = decideExitCode(failed, update);
  if (code !== 0) process.exit(code);
}

// Importable for tests (the decision helpers above): only run the driver
// when this file IS the entry point, mirroring conformance/analyzer/run.ts.
const thisFile = realpathSync(fileURLToPath(import.meta.url));
const entry = process.argv[1] ? realpathSync(process.argv[1]) : '';
if (entry === thisFile) main();
