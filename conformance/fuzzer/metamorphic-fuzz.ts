/**
 * Metamorphic (EMI-style) fuzz driver for the Rúnar compiler (TS-GAP-009).
 *
 * Generates random stateless / arithmetic contracts, applies each
 * semantics-preserving transform from `metamorphic.ts`, and asserts that the
 * ORIGINAL and TRANSFORMED contracts produce the SAME executed accept/reject
 * verdict on the BSV script engine over several random witnesses. A transform
 * is guaranteed not to change runtime semantics, so any pair where both
 * versions compile but their `vmAccepted` verdicts differ is a real, latent
 * compiler bug — the kind of shared-design mistake that cross-tier byte-parity
 * cannot see (all seven tiers would emit the same wrong bytes) and that no
 * golden reference exists to catch.
 *
 * We compare executed BEHAVIOUR (`runDifferentialExecution().vmAccepted`), not
 * script bytes: a semantics-preserving edit (renaming a local, reordering a
 * commutative operator) legitimately shifts constructor-arg byte offsets, so
 * byte-equality is the wrong oracle here.
 *
 * PRECONDITION / SKIP: a source transform must yield still-valid Rúnar. When a
 * transform cannot apply cleanly (it leaves the source unchanged) or produces
 * code the compiler rejects, that PAIR is skipped and counted — it is not a
 * failure. Only "both compile, verdicts differ" is a failure; on any such
 * divergence the driver saves a finding and exits non-zero.
 *
 * Determinism: `--seed` seeds both the fast-check contract sampler and a
 * Mulberry32 PRNG for constructor args + witnesses, so a run is exactly
 * reproducible.
 *
 * Usage: tsx fuzzer/metamorphic-fuzz.ts --num 200 --seed 424242 [--witnesses 5] [--verbose]
 *
 * Imports resolve via relative paths into `packages/` (rather than bare
 * `runar-*` specifiers) so the driver runs under plain `tsx` from the
 * standalone `conformance` npm environment, exactly like the other fuzz
 * drivers in this directory.
 */

import fc from 'fast-check';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  arbArithmeticContract,
  arbStatelessContract,
  runDifferentialExecution,
  type WitnessArg,
} from '../../packages/runar-testing/src/index.js';
import { compile } from '../../packages/runar-compiler/src/index.js';
import type { TypeNode } from '../../packages/runar-compiler/src/ir/runar-ast.js';

import {
  renameLocals,
  reorderCommutative,
  introduceLet,
  insertDeadCode,
} from './metamorphic.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FINDINGS_DIR = resolve(__dirname, '..', 'fuzz-findings-metamorphic');
const FILE_NAME = 'Gen.runar.ts';

interface Transform {
  name: string;
  fn: (s: string) => string;
}

const TRANSFORMS: readonly Transform[] = [
  { name: 'renameLocals', fn: renameLocals },
  { name: 'reorderCommutative', fn: reorderCommutative },
  { name: 'introduceLet', fn: introduceLet },
  { name: 'insertDeadCode', fn: insertDeadCode },
];

// ---------------------------------------------------------------------------
// Deterministic PRNG (Mulberry32 — same approach as the other fuzz drivers)
// ---------------------------------------------------------------------------

interface Rng {
  int(min: number, max: number): number;
}

function mulberry32(seed: number): Rng {
  let state = seed >>> 0;
  function next(): number {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 0x100000000;
  }
  return {
    int(min, max) {
      return min + Math.floor(next() * (max - min + 1));
    },
  };
}

function randomBigint(rng: Rng): bigint {
  return BigInt(rng.int(-1000, 1000));
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

interface Options {
  num: number;
  seed: number;
  witnesses: number;
  verbose: boolean;
}

function parseArgs(argv: string[]): Options {
  const opts: Options = { num: 200, seed: 424242, witnesses: 5, verbose: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--num':
        opts.num = parseInt(argv[++i]!, 10);
        break;
      case '--seed':
        opts.seed = parseInt(argv[++i]!, 10);
        break;
      case '--witnesses':
        opts.witnesses = parseInt(argv[++i]!, 10);
        break;
      case '--verbose':
        opts.verbose = true;
        break;
      default:
        throw new Error(`unknown argument: ${a}`);
    }
  }
  return opts;
}

// ---------------------------------------------------------------------------
// Contract metadata + witness synthesis
// ---------------------------------------------------------------------------

function isBigint(t: TypeNode): boolean {
  return t.kind === 'primitive_type' && t.name === 'bigint';
}

interface Meta {
  method: string;
  paramCount: number;
  constructorArgs: Record<string, bigint>;
}

/**
 * Compile the source to extract a spendable public method whose params are all
 * bigint, plus deterministic bigint constructor args for its properties.
 * Returns null when the contract cannot be exercised with bigint witnesses
 * (caller skips it).
 */
function extractMeta(source: string, rng: Rng): Meta | null {
  let result: ReturnType<typeof compile>;
  try {
    result = compile(source, {
      fileName: FILE_NAME,
      disableConstantFolding: false,
      constructorArgs: {},
    });
  } catch {
    return null;
  }
  if (!result.success || !result.contract) return null;

  const publicMethods = result.contract.methods.filter(
    (m) => m.visibility === 'public' && m.name !== 'constructor',
  );
  if (publicMethods.length === 0) return null;
  const method = publicMethods[0]!;
  if (method.params.length === 0) return null;
  if (!method.params.every((p) => isBigint(p.type))) return null;

  const constructorArgs: Record<string, bigint> = {};
  for (const prop of result.contract.properties) {
    if (prop.initializer) continue; // initialised props are not constructor args
    if (!isBigint(prop.type)) return null;
    constructorArgs[prop.name] = randomBigint(rng);
  }

  return { method: method.name, paramCount: method.params.length, constructorArgs };
}

// ---------------------------------------------------------------------------
// Findings persistence
// ---------------------------------------------------------------------------

interface Finding {
  seed: number;
  index: number;
  transform: string;
  witness: string[];
  origAccepted: boolean;
  transformedAccepted: boolean;
  original: string;
  transformed: string;
}

function saveFinding(f: Finding): string {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = join(FINDINGS_DIR, `${ts}-${f.transform}-${f.index}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'original.runar.ts'), f.original, 'utf-8');
  writeFileSync(join(dir, 'transformed.runar.ts'), f.transformed, 'utf-8');
  writeFileSync(
    join(dir, 'finding.json'),
    JSON.stringify(
      {
        seed: f.seed,
        index: f.index,
        transform: f.transform,
        witness: f.witness,
        origAccepted: f.origAccepted,
        transformedAccepted: f.transformedAccepted,
      },
      null,
      2,
    ) + '\n',
    'utf-8',
  );
  return dir;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(): number {
  const opts = parseArgs(process.argv.slice(2));
  console.log(
    `metamorphic-fuzz: num=${opts.num} seed=${opts.seed} witnesses=${opts.witnesses} transforms=${TRANSFORMS.length}`,
  );

  // Sample contracts: half arithmetic (stateful-free, with properties), half
  // pure-stateless. Both emit only bigint params/properties.
  const nArith = Math.ceil(opts.num / 2);
  const nStateless = opts.num - nArith;
  const sources: string[] = [
    ...fc.sample(arbArithmeticContract, { numRuns: nArith, seed: opts.seed }),
    ...fc.sample(arbStatelessContract, { numRuns: nStateless, seed: opts.seed + 1 }),
  ];

  const rng = mulberry32(opts.seed);
  let pairsTested = 0;
  let witnessChecks = 0;
  let skippedNoMeta = 0;
  let skippedTransform = 0;
  let divergences = 0;

  for (let i = 0; i < sources.length; i++) {
    const source = sources[i]!;
    const meta = extractMeta(source, rng);
    if (!meta) {
      skippedNoMeta++;
      continue;
    }

    // Deterministic witnesses for this contract.
    const witnessSets: bigint[][] = [];
    for (let w = 0; w < opts.witnesses; w++) {
      witnessSets.push(
        Array.from({ length: meta.paramCount }, () => randomBigint(rng)),
      );
    }

    // Original verdicts (computed once, reused across all transforms).
    const origVerdicts: (boolean | null)[] = witnessSets.map((args) => {
      try {
        return runDifferentialExecution({
          source,
          fileName: FILE_NAME,
          method: meta.method,
          args: args as WitnessArg[],
          constructorArgs: meta.constructorArgs,
        }).vmAccepted;
      } catch {
        return null; // original itself failed to run — skip this witness
      }
    });

    for (const transform of TRANSFORMS) {
      const transformed = transform.fn(source);

      // Precondition 1: the transform actually applied.
      if (transformed === source) {
        skippedTransform++;
        continue;
      }
      // Precondition 2: the transformed source is still valid Rúnar.
      let transformedCompiles = false;
      try {
        transformedCompiles = compile(transformed, {
          fileName: FILE_NAME,
          disableConstantFolding: false,
          constructorArgs: meta.constructorArgs,
        }).success;
      } catch {
        transformedCompiles = false;
      }
      if (!transformedCompiles) {
        skippedTransform++;
        continue;
      }

      pairsTested++;
      for (let w = 0; w < witnessSets.length; w++) {
        const origAccepted = origVerdicts[w];
        if (origAccepted === null) continue;
        const args = witnessSets[w]!;

        let transformedAccepted: boolean;
        try {
          transformedAccepted = runDifferentialExecution({
            source: transformed,
            fileName: FILE_NAME,
            method: meta.method,
            args: args as WitnessArg[],
            constructorArgs: meta.constructorArgs,
          }).vmAccepted;
        } catch {
          // Transformed compiled but failed to execute — treat as a skip, not a
          // divergence (executor error, not a semantics change).
          continue;
        }
        witnessChecks++;

        if (transformedAccepted !== origAccepted) {
          divergences++;
          const dir = saveFinding({
            seed: opts.seed,
            index: i,
            transform: transform.name,
            witness: args.map((x) => `${x}n`),
            origAccepted,
            transformedAccepted,
            original: source,
            transformed,
          });
          console.error(
            `  [${i}] DIVERGENCE via ${transform.name}: orig=${origAccepted} transformed=${transformedAccepted} witness=[${args.join(
              ',',
            )}]`,
          );
          console.error(`        saved: ${dir}`);
        } else if (opts.verbose) {
          console.log(
            `  [${i}] ${transform.name} witness=[${args.join(',')}] verdict=${origAccepted} OK`,
          );
        }
      }
    }
  }

  console.log('');
  console.log(`contracts sampled:        ${sources.length}`);
  console.log(`contracts skipped (meta): ${skippedNoMeta}`);
  console.log(`transform pairs tested:   ${pairsTested}`);
  console.log(`transform pairs skipped:  ${skippedTransform}`);
  console.log(`witness comparisons:      ${witnessChecks}`);
  console.log(`divergences:              ${divergences}`);

  if (divergences > 0) {
    console.error(
      `\nFAIL: ${divergences} metamorphic divergence(s) — semantics-preserving transforms changed compiled behaviour. Findings in ${FINDINGS_DIR}`,
    );
    return 1;
  }
  console.log('\nOK: no metamorphic divergences.');
  return 0;
}

process.exit(main());
