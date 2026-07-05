/**
 * Randomized source-vs-script EXECUTION oracle (TS-GAP-001 randomized half,
 * TS-GAP-005).
 *
 * The `--anf` / `--ir` fuzzers are *parity* oracles: they only assert that all
 * seven tiers emit byte-identical hex. Seven tiers can agree on the SAME wrong
 * bytes and every parity check still passes. This harness closes that gap for
 * the randomized corpus: it GENERATES stateless, non-crypto contracts, renders
 * each to TypeScript source, and runs every generated spend through two
 * INDEPENDENT engines via the shared differential-execution oracle
 * (`packages/runar-testing/src/oracle`):
 *
 *   1. source semantics — the ANF `RunarInterpreter` (via `TestContract`)
 *   2. script semantics — the compiler's fold-ON deployed bytes executed on the
 *      `@bsv/sdk`-backed `ScriptVM`
 *
 * and asserts they AGREE on accept/reject. A divergence
 * (`interpreterAccepted !== vmAccepted`) is a real, shared-design compiler bug:
 * the two engines are independent implementations of the same source semantics.
 *
 * Scope (why this subset): the in-process oracle cannot execute contracts whose
 * spend needs a real transaction context or real crypto. We therefore restrict
 * the corpus to `arbGeneratedContract` — STATELESS `SmartContract`s whose bodies
 * are pure arithmetic / boolean / comparison / `abs`/`min`/`max` over bigint and
 * boolean params and readonly properties (no `checkSig`, no EC, no hash
 * preimage, no state continuation). Stateful and crypto contracts are covered by
 * the Go `script_execution_test.go` real-crypto path instead.
 *
 * Determinism: an effective seed drives BOTH the fast-check contract corpus
 * (`fc.sample`) and a Mulberry32 PRNG that synthesizes the per-spend input
 * vectors. Re-running with the same `--seed` reproduces the exact corpus, the
 * exact inputs, and the exact verdicts. Unseeded runs pick a random effective
 * seed and PRINT it so any finding is replayable.
 *
 * Findings: every divergence (and any compile/interpreter throw) is written to
 * `conformance/fuzz-findings-execute/` (rendered source + inputs + verdicts +
 * scripts) and makes the run exit non-zero.
 */

import fc from 'fast-check';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  arbGeneratedContract,
  renderTypeScript,
} from '../../packages/runar-testing/src/fuzzer/index.js';
import type {
  GeneratedContract,
  GeneratedMethod,
} from '../../packages/runar-testing/src/fuzzer/index.js';
import { runDifferentialExecution } from '../../packages/runar-testing/src/oracle/index.js';
import type { WitnessArg } from '../../packages/runar-testing/src/oracle/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = resolve(__dirname, '../..');

// ---------------------------------------------------------------------------
// Deterministic input synthesis
// ---------------------------------------------------------------------------

/**
 * Small deterministic RNG (mulberry32) — same implementation the ANF fuzzer
 * uses, so the harness doesn't depend on any fast-check internal for the
 * per-spend inputs. fast-check drives only the top-level contract corpus.
 */
function mulberry32(a: number): () => number {
  let state = a >>> 0;
  return function next(): number {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 0x100000000;
  };
}

/**
 * Bigint magnitude for synthesized inputs. Matches the generator's own literal
 * range (`arbBigintLiteralIR` draws in [-100, 100]) so inputs stay in the same
 * numeric domain the contracts were built for — this oracle probes accept/reject
 * LOGIC agreement, not integer-width edge cases (those are TS-GAP-010's boundary
 * corpus). Both ACCEPT and REJECT paths are exercised at this range.
 */
const INPUT_MAG = 100;

function makeSynthesizer(rng: () => number): {
  bigint: () => bigint;
  boolean: () => boolean;
} {
  const intInRange = (min: number, max: number): number =>
    min + Math.floor(rng() * (max - min + 1));
  return {
    bigint: () => BigInt(intInRange(-INPUT_MAG, INPUT_MAG)),
    boolean: () => rng() < 0.5,
  };
}

/** Synthesize one value for a bigint/boolean param or property. */
function synthValue(
  type: string,
  synth: { bigint: () => bigint; boolean: () => boolean },
): WitnessArg {
  return type === 'boolean' ? synth.boolean() : synth.bigint();
}

/**
 * De-duplicate methods by name. `arbGeneratedContract` samples each method's
 * name independently from `method0..9`, so a contract can carry two methods
 * with the same name — which renders to duplicate TS methods and fails to
 * compile. Keep the first occurrence of each name (this is a corpus-shaping
 * fix, not a behavioral one: a duplicate-name contract is not a valid program).
 */
function dedupeMethods(methods: GeneratedMethod[]): GeneratedMethod[] {
  const seen = new Set<string>();
  const out: GeneratedMethod[] = [];
  for (const m of methods) {
    if (seen.has(m.name)) continue;
    seen.add(m.name);
    out.push(m);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Findings persistence
// ---------------------------------------------------------------------------

interface ExecFinding {
  seed: number;
  contractIndex: number;
  reason: string;
  contractName: string;
  method: string;
  source: string;
  constructorArgs: Record<string, string>;
  args: string[];
  interpreterAccepted?: boolean;
  vmAccepted?: boolean;
  lockingHex?: string;
  witnessHex?: string;
  interpreterError?: string;
  vmError?: string;
  throwMessage?: string;
}

function jsonifyArg(v: WitnessArg): string {
  if (typeof v === 'bigint') return `${v}n`;
  if (typeof v === 'boolean') return String(v);
  return `0x${Buffer.from(v).toString('hex')}`;
}

function saveFinding(dir: string, f: ExecFinding): string {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const out = join(dir, `${ts}-${f.contractName}-${f.method}`);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'contract.runar.ts'), f.source + '\n', 'utf-8');
  writeFileSync(join(out, 'finding.json'), JSON.stringify(f, null, 2) + '\n', 'utf-8');
  return out;
}

// ---------------------------------------------------------------------------
// Public harness
// ---------------------------------------------------------------------------

export interface ExecuteDifferentialOptions {
  /** Number of contracts to generate. */
  numContracts: number;
  /** RNG seed; when omitted a random effective seed is chosen and reported. */
  seed?: number;
  /** Input vectors per (contract, method). Default 6. */
  inputsPerMethod?: number;
  /** Wall-clock budget in ms; harness returns early once exceeded. */
  timeBudgetMs?: number;
  /** Where to dump findings. Default `conformance/fuzz-findings-execute/`. */
  findingsDir?: string;
  /** Verbose per-case log. */
  verbose?: boolean;
}

export interface ExecuteDifferentialReport {
  totalContracts: number;
  contractsRun: number;
  /** Total (contract, method, input-vector) spends executed. */
  casesRun: number;
  /** Spends where both engines accepted. */
  acceptCount: number;
  /** Spends where both engines rejected. */
  rejectCount: number;
  /** interpreterAccepted !== vmAccepted — the real bug signal. */
  divergenceCount: number;
  /** Compile / interpreter / VM throws (a distinct anomaly class). */
  errorCount: number;
  earlyStop: boolean;
  durationMs: number;
  /** Directories of saved findings (divergences + errors). */
  findings: string[];
  /** The seed that reproduces this exact run. */
  effectiveSeed: number;
}

export async function runExecuteDifferential(
  opts: ExecuteDifferentialOptions,
): Promise<ExecuteDifferentialReport> {
  const effectiveSeed =
    opts.seed ?? Math.floor(Math.random() * 0x7fffffff);
  const inputsPerMethod = opts.inputsPerMethod ?? 6;
  const findingsDir =
    opts.findingsDir ?? join(ROOT, 'conformance', 'fuzz-findings-execute');

  // Deterministic contract corpus (stateless, non-crypto only).
  const contracts = fc.sample(arbGeneratedContract, {
    numRuns: opts.numContracts,
    seed: effectiveSeed,
  }) as GeneratedContract[];

  // Deterministic per-spend input RNG, seeded from the same effective seed.
  const synth = makeSynthesizer(mulberry32(effectiveSeed ^ 0x9e3779b9));

  const start = Date.now();
  let contractsRun = 0;
  let casesRun = 0;
  let acceptCount = 0;
  let rejectCount = 0;
  let divergenceCount = 0;
  let errorCount = 0;
  let earlyStop = false;
  const findings: string[] = [];

  for (let ci = 0; ci < contracts.length; ci++) {
    if (opts.timeBudgetMs !== undefined && Date.now() - start > opts.timeBudgetMs) {
      earlyStop = true;
      break;
    }

    const contract = contracts[ci]!;
    const methods = dedupeMethods(contract.methods);
    const normalized: GeneratedContract = { ...contract, methods };
    const source = renderTypeScript(normalized);
    const fileName = `${contract.name}.runar.ts`;
    contractsRun += 1;

    for (const method of methods) {
      for (let k = 0; k < inputsPerMethod; k++) {
        if (
          opts.timeBudgetMs !== undefined &&
          Date.now() - start > opts.timeBudgetMs
        ) {
          earlyStop = true;
          break;
        }

        // Fresh random constructor + method arguments per input vector.
        const constructorArgs: Record<string, WitnessArg> = {};
        for (const p of contract.properties) {
          constructorArgs[p.name] = synthValue(p.type, synth);
        }
        const args: WitnessArg[] = method.params.map((p) =>
          synthValue(p.type, synth),
        );
        casesRun += 1;

        try {
          const r = runDifferentialExecution({
            source,
            fileName,
            method: method.name,
            args,
            constructorArgs,
          });

          if (r.agrees) {
            if (r.vmAccepted) acceptCount += 1;
            else rejectCount += 1;
            if (opts.verbose) {
              console.log(
                `  ok ${contract.name}.${method.name} → ${r.vmAccepted ? 'accept' : 'reject'}`,
              );
            }
          } else {
            divergenceCount += 1;
            const dir = saveFinding(findingsDir, {
              seed: effectiveSeed,
              contractIndex: ci,
              reason: `exec divergence: interpreter=${r.interpreterAccepted} vm=${r.vmAccepted}`,
              contractName: contract.name,
              method: method.name,
              source,
              constructorArgs: Object.fromEntries(
                Object.entries(constructorArgs).map(([kk, vv]) => [kk, jsonifyArg(vv)]),
              ),
              args: args.map(jsonifyArg),
              interpreterAccepted: r.interpreterAccepted,
              vmAccepted: r.vmAccepted,
              lockingHex: r.lockingHex,
              witnessHex: r.witnessHex,
              interpreterError: r.interpreterError,
              vmError: r.vmError,
            });
            findings.push(dir);
            console.error(
              `DIVERGENCE ${contract.name}.${method.name}: interpreter=${r.interpreterAccepted} vm=${r.vmAccepted} (${r.vmError ?? 'no vm error'})\n  saved: ${dir}`,
            );
          }
        } catch (e) {
          errorCount += 1;
          const message = e instanceof Error ? e.message : String(e);
          const dir = saveFinding(findingsDir, {
            seed: effectiveSeed,
            contractIndex: ci,
            reason: `exec error: ${message}`,
            contractName: contract.name,
            method: method.name,
            source,
            constructorArgs: Object.fromEntries(
              Object.entries(constructorArgs).map(([kk, vv]) => [kk, jsonifyArg(vv)]),
            ),
            args: args.map(jsonifyArg),
            throwMessage: message,
          });
          findings.push(dir);
          console.error(
            `ERROR ${contract.name}.${method.name}: ${message}\n  saved: ${dir}`,
          );
        }
      }
      if (earlyStop) break;
    }
  }

  return {
    totalContracts: contracts.length,
    contractsRun,
    casesRun,
    acceptCount,
    rejectCount,
    divergenceCount,
    errorCount,
    earlyStop,
    durationMs: Date.now() - start,
    findings,
    effectiveSeed,
  };
}
