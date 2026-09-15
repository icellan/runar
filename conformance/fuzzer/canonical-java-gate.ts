/**
 * GAP-002 (Java) — deterministic Java canonicalJson PR gate.
 *
 * canonicalJson is a WIRE-PROTOCOL primitive: a signature produced by one SDK
 * tier must verify under every other tier, so all seven tiers MUST produce
 * byte-identical canonicalJson (CLAUDE.md §"Seven SDKs Must Stay in Sync"). The
 * randomized cross-tier fuzzer (`canonical-json-differential.ts`) drives each
 * non-TS tier through a single-shot CLI shim — one process per case. For six of
 * the seven tiers that is cheap, but the Java shim forks a JVM per case
 * (`gradle runCanonicalise`), which is too slow / flake-prone to include in the
 * per-PR fuzz gate, so the randomized 7-tier run only lands on the nightly path.
 *
 * That leaves a hole: a Java-only canonicalJson divergence over the tricky
 * surface the fuzzer explores (ECMA-262 float boundaries, UTF-16 key ordering,
 * lone-surrogate rejection, deep nesting) would NOT fail any PR gate — it would
 * silently break Java<->other-tier signatures until a nightly run caught it.
 * The ~21 fixed `canonical_json_vectors` in the sdk-envelope fixture (checked on
 * PRs by EnvelopeInteropTest) cover only a thin slice of that surface.
 *
 * This gate closes the hole deterministically and fast:
 *   1. It regenerates the EXACT corpus the randomized fuzzer would produce for a
 *      fixed seed (same `mulberry32((seed+i))` per-case PRNG + `genCase`), so it
 *      spans the same tricky surface.
 *   2. It computes the reference canonical bytes for each case with the TS
 *      reference (`runTs` -> `canonicalJsonStringify`) — the authoritative impl.
 *   3. It pushes every request through the Java shim's BATCH entrypoint
 *      (`gradle -q runCanonicaliseBatch`) in a SINGLE JVM, and byte-compares each
 *      Java output line against the reference (rejections normalised to a single
 *      token, mirroring the fuzzer).
 *
 * Deterministic (fixed seed), one JVM cold-start total, hard-fails on any
 * divergence — suitable for a PR merge gate. A divergence is a real latent bug
 * and is printed with the offending request + both outputs.
 *
 * Usage: tsx conformance/fuzzer/canonical-java-gate.ts [--seed N] [--num N]
 */

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  genCase,
  caseToRequest,
  runTs,
  loadCanonical,
  mulberry32,
  normaliseOutcome,
  type GenCase,
} from './canonical-json-differential.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = resolve(__dirname, '../..');
const JAVA_DIR = resolve(ROOT, 'packages/runar-java');
const GRADLEW = resolve(JAVA_DIR, 'gradlew');

interface Options {
  seed: number;
  num: number;
  timeoutMs: number;
}

function parseArgs(argv: string[]): Options {
  // Same fixed default seed as the six-tier PR fuzz gate, so this gate replays
  // the identical corpus a developer can reproduce locally.
  const opts: Options = { seed: 20020602, num: 256, timeoutMs: 300_000 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--seed') opts.seed = parseInt(argv[++i] ?? '', 10);
    else if (a === '--num') opts.num = parseInt(argv[++i] ?? '', 10);
    else if (a === '--timeout-ms') opts.timeoutMs = parseInt(argv[++i] ?? '', 10);
    else if (a === '--help' || a === '-h') {
      console.log('Usage: tsx canonical-java-gate.ts [--seed N] [--num N] [--timeout-ms N]');
      process.exit(0);
    }
  }
  if (!Number.isFinite(opts.seed) || !Number.isFinite(opts.num) || opts.num <= 0) {
    console.error('canonical-java-gate: invalid --seed / --num');
    process.exit(2);
  }
  return opts;
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));

  if (!existsSync(GRADLEW)) {
    console.error(`canonical-java-gate: Java gradle wrapper not found at ${GRADLEW}`);
    console.error('Build the Java SDK first (packages/runar-java). This gate REQUIRES Java.');
    process.exit(2);
  }

  const canon = await loadCanonical();

  // 1+2. Regenerate the fuzzer's exact corpus and the TS reference output.
  const cases: GenCase[] = [];
  const requests: string[] = [];
  const references: string[] = [];
  for (let i = 0; i < opts.num; i++) {
    const rng = mulberry32((opts.seed + i) >>> 0);
    const c = genCase(rng);
    cases.push(c);
    requests.push(caseToRequest(c));
    references.push(runTs(canon, c));
  }

  console.log(
    `canonical-java-gate: seed=${opts.seed} num=${opts.num} — driving Java shim (batch, one JVM)…`,
  );

  // 3. One JVM cold-start for the whole corpus.
  const started = Date.now();
  const r = spawnSync(GRADLEW, ['-q', 'runCanonicaliseBatch'], {
    cwd: JAVA_DIR,
    input: requests.join('\n') + '\n',
    encoding: 'utf-8',
    timeout: opts.timeoutMs,
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const durationMs = Date.now() - started;

  if (r.error) {
    console.error(`canonical-java-gate: failed to run Java batch shim: ${r.error.message}`);
    process.exit(2);
  }
  // No response line is ever empty (canonical output for `""` is `""`, for null
  // is `null`, rejections carry the prefix), so dropping empties only strips the
  // trailing newline's split artefact.
  const outLines = (r.stdout ?? '').split('\n').filter((l) => l.length > 0);

  if (outLines.length !== opts.num) {
    console.error(
      `canonical-java-gate: expected ${opts.num} Java response lines, got ${outLines.length}.`,
    );
    console.error('  This is a framing/protocol failure, not necessarily a canonicalJson bug.');
    console.error(`  stderr: ${(r.stderr ?? '').slice(0, 2000)}`);
    console.error(`  first lines: ${JSON.stringify(outLines.slice(0, 5))}`);
    process.exit(2);
  }

  let mismatches = 0;
  for (let i = 0; i < opts.num; i++) {
    const ref = references[i]!;
    const java = outLines[i]!;
    if (normaliseOutcome(ref) !== normaliseOutcome(java)) {
      mismatches += 1;
      console.log(`  [${i}] MISMATCH  seed=${opts.seed + i}`);
      console.log(`        request   = ${requests[i]}`);
      console.log(`        ts(ref)   = ${JSON.stringify(ref)}`);
      console.log(`        java      = ${JSON.stringify(java)}`);
    }
  }

  console.log(
    `canonical-java-gate: ${opts.num} cases, ${mismatches} divergence(s), ${durationMs} ms.`,
  );

  if (mismatches > 0) {
    console.error(
      `canonical-java-gate: FAIL — Java canonicalJson diverges from the TS reference on ${mismatches} case(s).`,
    );
    console.error(
      'This breaks Java<->other-tier signatures. Fix Java Envelope.canonicalJson, do NOT edit this gate.',
    );
    process.exit(1);
  }
  console.log('canonical-java-gate: PASS — Java canonicalJson is byte-identical to the TS reference.');
}

main().catch((e) => {
  console.error(`canonical-java-gate: unexpected error: ${(e as Error).stack ?? e}`);
  process.exit(2);
});
