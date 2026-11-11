// ---------------------------------------------------------------------------
// conformance/sdk-vertical/generate.ts
// ---------------------------------------------------------------------------
//
// Regenerate the vertical-pin fixtures:
//   artifacts/<Contract>.json     compiled by the reference (TS) compiler
//   cases/<row>/input.json        {artifact, constructorArgs} — the same shape
//                                 conformance/sdk-output uses, so the existing
//                                 per-tier SDK drivers run against it unchanged
//   cases/<row>/expected-code-part.hex   INDEPENDENTLY DERIVED (reference/)
//   cases/<row>/expected-vertical.json   INDEPENDENTLY DERIVED (reference/)
//   cases/<row>/expected-readback.json   INDEPENDENTLY DERIVED (reference/readback.ts):
//                                 the honest locking script + tampered scripts,
//                                 and what matchesArtifact /
//                                 extractConstructorArgs must say about each
//
// The goldens are written from `reference/derive.ts`, never from an SDK.
// Generation REFUSES to write a case whose artifact fails its own template
// claims, so a broken artifact cannot be laundered into a golden.
//
// Run:  cd conformance && npx tsx sdk-vertical/generate.ts
//
// `--check` recompiles contracts/*.runar.ts and asserts the result is
// DEEP-EQUAL (key-order-independent) to the checked-in artifacts/*.json AND
// to the artifact embedded in every cases/*/input.json, without writing
// anything. Nothing in the repo previously re-invoked the compiler against
// these fixtures at all — T2-T8/D2-D5 only ever inspected the committed
// artifact blob, so a compiler regression that changed `contracts/*.runar.ts`
// output could ship with every pin still green (remediation plan P0-3).
//
//   cd conformance && npx tsx sdk-vertical/generate.ts --check
//
// A failure here means one of two things: either the change to the compiler
// was INTENDED, in which case re-run without `--check` and review the golden
// diff before committing it — or it was NOT intended, in which case this is a
// compiler regression and the fix belongs in the compiler, not in a
// regenerated golden.
// ---------------------------------------------------------------------------

import { execFileSync } from 'child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

import { MATRIX } from './matrix.js';
import { deriveVertical, type RefArtifact } from './reference/derive.js';
import { deriveReadback } from './reference/readback.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HERE = __dirname;
const ROOT = resolve(join(HERE, '..', '..'));

const CONTRACTS_DIR = join(HERE, 'contracts');
const ARTIFACTS_DIR = join(HERE, 'artifacts');
const CASES_DIR = join(HERE, 'cases');
const TMP_DIR = join(HERE, '.tmp');

/** Fields that carry build-time noise or bulk IR; the SDK drivers never read
 *  them and keeping them would make every golden churn on unrelated changes. */
const STRIPPED = ['ir', 'anf', 'asm', 'sourceMap', 'buildTimestamp'] as const;

function compileContract(name: string): RefArtifact {
  const source = join(CONTRACTS_DIR, `${name}.runar.ts`);
  if (!existsSync(source)) throw new Error(`missing contract source ${source}`);

  // cwd MUST be conformance/ (not ROOT) so `npx` resolves `tsx` from
  // conformance/node_modules/.bin regardless of the caller's own PATH.
  // Previously this ran with `cwd: ROOT`, which only worked when generate.ts
  // itself had been launched as `cd conformance && npx tsx generate.ts` —
  // that outer `npx` prepends conformance/node_modules/.bin to the inherited
  // PATH, which this execFileSync silently relied on. Calling compileContract
  // from a different process (e.g. `checkArtifacts()` imported into a vitest
  // run started from the repo root, plan P0-3) exposed it: `sh: tsx: command
  // not found`, because ROOT/node_modules/.bin has no tsx.
  execFileSync(
    'npx',
    ['tsx', join(ROOT, 'packages', 'runar-cli', 'src', 'bin.ts'), 'compile', source, '-o', TMP_DIR],
    { cwd: join(ROOT, 'conformance'), stdio: 'pipe' },
  );

  const artifactPath = join(TMP_DIR, `${name}.runar.json`);
  if (!existsSync(artifactPath)) throw new Error(`compiler produced no artifact at ${artifactPath}`);
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf-8')) as Record<string, unknown>;
  for (const f of STRIPPED) delete artifact[f];
  return artifact as unknown as RefArtifact;
}

function main(): void {
  mkdirSync(TMP_DIR, { recursive: true });
  mkdirSync(ARTIFACTS_DIR, { recursive: true });
  mkdirSync(CASES_DIR, { recursive: true });

  const contracts = [...new Set(MATRIX.map((r) => r.contract))];
  const artifacts = new Map<string, RefArtifact>();
  for (const c of contracts) {
    console.log(`Compiling ${c}...`);
    const a = compileContract(c);
    artifacts.set(c, a);
    writeFileSync(join(ARTIFACTS_DIR, `${c}.json`), JSON.stringify(a, null, 2) + '\n');
  }

  // Drop case dirs that are no longer in the matrix, so a removed row cannot
  // leave a stale golden behind that nothing runs.
  const wanted = new Set(MATRIX.map((r) => r.name));
  if (existsSync(CASES_DIR)) {
    for (const d of readdirSync(CASES_DIR, { withFileTypes: true })) {
      if (d.isDirectory() && !wanted.has(d.name)) {
        rmSync(join(CASES_DIR, d.name), { recursive: true });
        console.log(`  removed stale case ${d.name}`);
      }
    }
  }

  let failures = 0;
  for (const row of MATRIX) {
    const artifact = artifacts.get(row.contract)!;
    const derivation = deriveVertical(artifact, row.constructorArgs);

    if (derivation.violations.length > 0) {
      failures++;
      console.error(`\n[FAIL] ${row.name}: refusing to write a golden for a violating case`);
      for (const v of derivation.violations) console.error(`    ${v.code}: ${v.message}`);
      continue;
    }

    const dir = join(CASES_DIR, row.name);
    mkdirSync(dir, { recursive: true });

    writeFileSync(
      join(dir, 'input.json'),
      JSON.stringify({ artifact, constructorArgs: row.constructorArgs }, null, 2) + '\n',
    );
    writeFileSync(join(dir, 'expected-code-part.hex'), derivation.codePartHex + '\n');
    writeFileSync(
      join(dir, 'expected-vertical.json'),
      JSON.stringify(
        {
          case: row.name,
          contract: row.contract,
          valueClass: row.valueClass,
          constructorArgs: row.constructorArgs,
          codePartByteLength: derivation.codePartByteLength,
          slots: derivation.slots,
          templateCodeSeparators: derivation.templateCodeSeparators,
          deployedCodeSeparators: derivation.deployedCodeSeparators,
          codeSepSlotValues: derivation.codeSepSlotValues,
        },
        null,
        2,
      ) + '\n',
    );
    const readback = deriveReadback(artifact, row.constructorArgs);
    writeFileSync(
      join(dir, 'expected-readback.json'),
      JSON.stringify({ case: row.name, contract: row.contract, ...readback }, null, 2) + '\n',
    );
    console.log(
      `  wrote ${row.name} (${derivation.codePartByteLength} B code part, ${readback.tampers.length} readback tampers)`,
    );
  }

  rmSync(TMP_DIR, { recursive: true, force: true });

  if (failures > 0) {
    console.error(`\n${failures} case(s) failed their vertical derivation; goldens not written.`);
    process.exit(1);
  }
  console.log(`\nDone: ${MATRIX.length} cases.`);
}

// ---------------------------------------------------------------------------
// --check: recompile and diff against the checked-in goldens, write nothing.
// ---------------------------------------------------------------------------

/** Recursively sort object keys so JSON.stringify comparison is key-order
 *  independent (the compiler makes no ordering guarantee on artifact JSON). */
function canonicalize(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonicalize);
  if (v !== null && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = canonicalize((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

/** Locate the first differing script byte, so a `--check` failure names an
 *  exact offset instead of dumping two multi-KB hex strings. */
function firstDiffByte(expectedHex: string, actualHex: string): string {
  const n = Math.min(expectedHex.length, actualHex.length);
  for (let i = 0; i < n; i += 2) {
    if (expectedHex.slice(i, i + 2) !== actualHex.slice(i, i + 2)) {
      return `first differing byte at offset ${i / 2}: expected 0x${expectedHex.slice(i, i + 2)}, actual 0x${actualHex.slice(i, i + 2)}`;
    }
  }
  if (expectedHex.length !== actualHex.length) {
    return `identical for ${n / 2} bytes, then lengths differ (expected ${expectedHex.length / 2} B, actual ${actualHex.length / 2} B)`;
  }
  return 'identical';
}

/** Per-key comparison between two artifact objects (or two of the same
 *  sub-shape). Exported so vertical-pins.test.ts can red-proof it directly,
 *  without shelling out to the compiler. */
export function diffArtifact(
  label: string,
  expected: Record<string, unknown>,
  actual: Record<string, unknown>,
): string[] {
  const issues: string[] = [];
  const keys = new Set([...Object.keys(expected), ...Object.keys(actual)]);
  for (const k of [...keys].sort()) {
    const e = canonicalize(expected[k]);
    const a = canonicalize(actual[k]);
    if (JSON.stringify(e) === JSON.stringify(a)) continue;
    if (k === 'script' && typeof expected[k] === 'string' && typeof actual[k] === 'string') {
      issues.push(`${label}: '${k}' differs — ${firstDiffByte(expected[k] as string, actual[k] as string)}`);
    } else {
      issues.push(`${label}: '${k}' differs\n      expected: ${JSON.stringify(e)}\n      actual:   ${JSON.stringify(a)}`);
    }
  }
  return issues;
}

export interface CheckResult {
  ok: boolean;
  issues: string[];
}

/**
 * Recompile every contract in MATRIX and assert the result matches
 * artifacts/<Contract>.json AND the artifact embedded in every
 * cases/<row>/input.json for that contract, byte for byte. Writes nothing.
 * Also flags case directories with no matching MATRIX row, and MATRIX rows
 * with no case directory, so the two never drift apart silently.
 */
export function checkArtifacts(): CheckResult {
  mkdirSync(TMP_DIR, { recursive: true });
  const issues: string[] = [];

  const contracts = [...new Set(MATRIX.map((r) => r.contract))];
  const fresh = new Map<string, RefArtifact>();
  for (const c of contracts) {
    const freshArtifact = compileContract(c);
    fresh.set(c, freshArtifact);

    const goldenPath = join(ARTIFACTS_DIR, `${c}.json`);
    if (!existsSync(goldenPath)) {
      issues.push(`artifacts/${c}.json is missing — run 'npx tsx sdk-vertical/generate.ts'`);
      continue;
    }
    const golden = JSON.parse(readFileSync(goldenPath, 'utf-8')) as Record<string, unknown>;
    issues.push(...diffArtifact(`artifacts/${c}.json`, golden, freshArtifact as unknown as Record<string, unknown>));
  }

  const wanted = new Map(MATRIX.map((r) => [r.name, r]));
  if (existsSync(CASES_DIR)) {
    for (const d of readdirSync(CASES_DIR, { withFileTypes: true })) {
      if (!d.isDirectory()) continue;
      const row = wanted.get(d.name);
      if (!row) {
        issues.push(`cases/${d.name} has no matching row in MATRIX (stale case dir — run generate.ts)`);
        continue;
      }
      const inputPath = join(CASES_DIR, d.name, 'input.json');
      if (!existsSync(inputPath)) {
        issues.push(`cases/${d.name}/input.json is missing — run 'npx tsx sdk-vertical/generate.ts'`);
        continue;
      }
      const input = JSON.parse(readFileSync(inputPath, 'utf-8')) as { artifact: Record<string, unknown> };
      const freshArtifact = fresh.get(row.contract)!;
      issues.push(
        ...diffArtifact(`cases/${d.name}/input.json`, input.artifact, freshArtifact as unknown as Record<string, unknown>),
      );
    }
  }
  for (const row of MATRIX) {
    if (!existsSync(join(CASES_DIR, row.name))) {
      issues.push(`MATRIX row '${row.name}' has no case dir under cases/ — run 'npx tsx sdk-vertical/generate.ts'`);
    }
  }

  rmSync(TMP_DIR, { recursive: true, force: true });
  return { ok: issues.length === 0, issues };
}

function runCheckCli(): void {
  const result = checkArtifacts();
  if (result.ok) {
    console.log(`OK: ${MATRIX.length} matrix rows match a fresh recompile of contracts/*.runar.ts.`);
    return;
  }
  console.error(`${result.issues.length} issue(s) — a fresh recompile does NOT match the checked-in goldens:\n`);
  for (const i of result.issues) console.error(`  ${i}`);
  console.error(
    `\nIf this compiler change is INTENDED: run 'npx tsx sdk-vertical/generate.ts' and review the golden diff.` +
      `\nIf it is NOT intended: you have found a compiler regression — do not regenerate.`,
  );
  process.exit(1);
}

// Run the CLI only when invoked as a program, so vertical-pins.test.ts (and
// generate.ts's own --check consumers) can import checkArtifacts/diffArtifact
// without triggering a recompile-and-write as a side effect of the import.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  if (process.argv.includes('--check')) {
    runCheckCli();
  } else {
    main();
  }
}
