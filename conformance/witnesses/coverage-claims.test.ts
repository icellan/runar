/**
 * Ledger honesty gate (audit findings #P0-1, #11, #14, #24).
 *
 * `coverage-ledger.json` (formerly split across `crypto-exempt.json` and
 * `harness-inapplicable.json`) used to carry only a
 * free-text `reason` string. Membership in the list was treated as "covered"
 * by `completeness.test.ts` with NO verification that the claimed coverage
 * (e.g. "Covered by the Go tx-context path") is actually true. Several
 * entries claimed a `conformance/script_execution_test.go` execution path
 * that does not reference the fixture at all.
 *
 * Every entry now carries a structured `coveredBy` field. This test proves
 * each claim by grepping the artifact it points to — it does not trust the
 * free-text `reason`/`cause` fields, which remain for human readability only.
 *
 * `coveredBy.kind` values:
 *   - "go-script-exec"          — the fixture name is literally compiled and
 *                                  executed by conformance/script_execution_test.go
 *                                  (`compileRúnar("<fixture>", ...)`).
 *   - "go-family-exec"          — the fixture's underlying primitive (not the
 *                                  literal fixture contract) is exercised by a
 *                                  real Go test function in script_execution_test.go
 *                                  via an inline reconstruction of the same codegen.
 *   - "integration"             — an on-chain regtest integration test
 *                                  (integration/<tier>/...) deploys/spends the
 *                                  fixture's actual .runar.ts source.
 *   - "interpreter-witness-exec"— the ANF interpreter executes the fixture with
 *                                  realistic tx-context witness bytes injected
 *                                  (TS tier only; not full Bitcoin Script bytes).
 *   - "anf-cross-tier-parity"   — conformance/anf-interpreter/cross-interpreter.test.ts
 *                                  runs the fixture's method through the ANF
 *                                  interpreter across all 7 tiers (TS reference
 *                                  + per-language drivers) and asserts the
 *                                  resulting state/outputs match a pinned
 *                                  golden. Proves cross-tier interpreter
 *                                  correctness; NOT a tx-context accept/reject
 *                                  differential against compiled script bytes.
 *   - "codegen-golden"          — byte-golden only, NOT executed by any engine.
 *                                  An honest opt-out: requires the fixture's own
 *                                  cross-tier expected-script.hex golden to exist,
 *                                  plus (where one exists) the family's dedicated
 *                                  codegen module file.
 *   - "go-only-nocodegen"       — compilers:["go"] proof-system fixture; no TS
 *                                  Stack-IR codegen exists so the TS-based
 *                                  differential/real-crypto harness cannot run it.
 *   - "sdk-corner"              — an acknowledged SDK/harness limitation with no
 *                                  further machine-checkable evidence beyond a
 *                                  non-empty `reason`.
 *   - "UNCOVERED"               — genuinely unexecuted anywhere; carries a
 *                                  mandatory `issue` field. completeness.test.ts
 *                                  does NOT count this fixture as covered, so the
 *                                  top-level completeness gate fails on it by
 *                                  design — the hole stays loud, not hidden.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..');
const TESTS_DIR = join(__dirname, '..', 'tests');
// Every Go file in conformance/ that compiles a fixture and spends it on the
// go-sdk consensus interpreter. This used to be script_execution_test.go alone,
// which meant a fixture executed by one of the newer per-finding execution
// tests could not honestly claim `go-script-exec` — the claim would be TRUE and
// the checker would call it false, pushing the entry toward a weaker kind or
// toward UNCOVERED. Scanning all of them makes the check match the claim.
const GO_EXEC_DIR = join(__dirname, '..');
const GO_EXEC_PATHS = readdirSync(GO_EXEC_DIR)
  .filter((f) => f === 'script_execution_test.go' || f.endsWith('_execution_test.go'))
  .sort()
  .map((f) => join(GO_EXEC_DIR, f));
if (GO_EXEC_PATHS.length === 0) {
  throw new Error(
    'no Go execution tests found in conformance/ — every go-script-exec claim ' +
    'would pass vacuously. Did the files move?',
  );
}
const GO_SCRIPT_EXEC_SRC = GO_EXEC_PATHS.map((f) => readFileSync(f, 'utf-8')).join('\n');

interface CoveredBy {
  kind: string;
  [key: string]: unknown;
}
interface LedgerEntry {
  fixture: string;
  coveredBy?: CoveredBy;
  [key: string]: unknown;
}

const LEDGER_FILE = 'coverage-ledger.json';

function loadLedger(): LedgerEntry[] {
  const doc = JSON.parse(readFileSync(join(__dirname, LEDGER_FILE), 'utf-8'));
  return doc.entries as LedgerEntry[];
}

/**
 * Closed `cause` vocabulary — the discriminator that survived the merge of the
 * old `crypto-exempt.json` (all its entries became `crypto-witness-infeasible`)
 * and `harness-inapplicable.json` (which already carried the other three).
 * Enforced so a typo cannot invent a new, unreviewed exemption axis.
 */
const CAUSES = new Set([
  'crypto-witness-infeasible',
  'stateful-harness-gap',
  'go-only',
  'interpreter-unsupported',
]);

// Per-family dedicated codegen module — only families that genuinely have one
// are listed; a "codegen-golden" entry for a family NOT in this map is still
// valid (e.g. a base builtin with no dedicated module) but only the fixture's
// own golden is checked.
const FAMILY_MODULE: Record<string, string> = {
  ec: 'packages/runar-compiler/src/passes/ec-codegen.ts',
  p256: 'packages/runar-compiler/src/passes/p256-p384-codegen.ts',
  p384: 'packages/runar-compiler/src/passes/p256-p384-codegen.ts',
  rabin: 'packages/runar-compiler/src/passes/rabin-codegen.ts',
  'slh-dsa': 'packages/runar-compiler/src/passes/slh-dsa-codegen.ts',
  wots: 'packages/runar-compiler/src/passes/wots-codegen.ts',
  blake3: 'packages/runar-compiler/src/passes/blake3-codegen.ts',
};

/** Verify one entry's coveredBy claim against the artifact it names. Returns
 * null if the claim is true, or a human-readable failure reason if false. */
function verifyClaim(entry: LedgerEntry): string | null {
  const cb = entry.coveredBy;
  if (!cb || typeof cb.kind !== 'string') {
    return `${entry.fixture}: missing coveredBy.kind`;
  }
  switch (cb.kind) {
    case 'UNCOVERED': {
      if (!cb.issue || typeof cb.issue !== 'string' || cb.issue.trim().length === 0) {
        return `${entry.fixture}: UNCOVERED requires a non-empty "issue" field`;
      }
      return null;
    }
    case 'go-script-exec': {
      const fx = typeof cb.fixture === 'string' ? cb.fixture : entry.fixture;
      const needle = `compileRúnar("${fx}"`;
      if (!GO_SCRIPT_EXEC_SRC.includes(needle)) {
        return `${entry.fixture}: go-script-exec claims "${needle}" in script_execution_test.go — not found`;
      }
      return null;
    }
    case 'go-family-exec': {
      const marker = cb.marker;
      if (typeof marker !== 'string' || marker.length === 0) {
        return `${entry.fixture}: go-family-exec requires a non-empty "marker" field`;
      }
      if (!GO_SCRIPT_EXEC_SRC.includes(`func ${marker}`)) {
        return `${entry.fixture}: go-family-exec claims "func ${marker}" in script_execution_test.go — not found`;
      }
      return null;
    }
    case 'integration': {
      const path = cb.path;
      if (typeof path !== 'string' || path.length === 0) {
        return `${entry.fixture}: integration requires a non-empty "path" field`;
      }
      const full = join(REPO_ROOT, path);
      if (!existsSync(full)) {
        return `${entry.fixture}: integration claims ${path} — file does not exist`;
      }
      const content = readFileSync(full, 'utf-8');
      if (!content.includes(entry.fixture)) {
        return `${entry.fixture}: integration claims ${path} — file does not reference fixture "${entry.fixture}"`;
      }
      return null;
    }
    case 'interpreter-witness-exec': {
      const path = cb.path;
      if (typeof path !== 'string' || path.length === 0) {
        return `${entry.fixture}: interpreter-witness-exec requires a non-empty "path" field`;
      }
      const full = join(REPO_ROOT, path);
      if (!existsSync(full)) {
        return `${entry.fixture}: interpreter-witness-exec claims ${path} — file does not exist`;
      }
      const content = readFileSync(full, 'utf-8');
      if (!content.includes(entry.fixture)) {
        return `${entry.fixture}: interpreter-witness-exec claims ${path} — file does not reference fixture "${entry.fixture}"`;
      }
      return null;
    }
    case 'anf-cross-tier-parity': {
      const inputFile = cb.input;
      if (typeof inputFile !== 'string' || inputFile.length === 0) {
        return `${entry.fixture}: anf-cross-tier-parity requires a non-empty "input" field`;
      }
      const anfDir = join(REPO_ROOT, 'conformance', 'anf-interpreter');
      const inputPath = join(anfDir, 'inputs', inputFile);
      if (!existsSync(inputPath)) {
        return `${entry.fixture}: anf-cross-tier-parity claims conformance/anf-interpreter/inputs/${inputFile} — does not exist`;
      }
      const inputCase = JSON.parse(readFileSync(inputPath, 'utf-8')).case;
      if (inputCase !== entry.fixture) {
        return `${entry.fixture}: anf-cross-tier-parity input ${inputFile} has case="${inputCase}", expected "${entry.fixture}"`;
      }
      const expectedPath = join(anfDir, 'expected', inputFile);
      if (!existsSync(expectedPath)) {
        return `${entry.fixture}: anf-cross-tier-parity claims a pinned golden at conformance/anf-interpreter/expected/${inputFile} — does not exist`;
      }
      return null;
    }
    case 'codegen-golden': {
      const family = cb.family;
      if (typeof family !== 'string' || family.length === 0) {
        return `${entry.fixture}: codegen-golden requires a non-empty "family" field`;
      }
      const goldenPath = join(TESTS_DIR, entry.fixture, 'expected-script.hex');
      if (!existsSync(goldenPath) || readFileSync(goldenPath, 'utf-8').trim().length === 0) {
        return `${entry.fixture}: codegen-golden claims a golden at ${goldenPath} — missing or empty`;
      }
      const modulePath = FAMILY_MODULE[family];
      if (modulePath && !existsSync(join(REPO_ROOT, modulePath))) {
        return `${entry.fixture}: codegen-golden family "${family}" claims module ${modulePath} — does not exist`;
      }
      return null;
    }
    case 'go-only-nocodegen': {
      const srcJsonPath = join(TESTS_DIR, entry.fixture, 'source.json');
      if (!existsSync(srcJsonPath)) {
        return `${entry.fixture}: go-only-nocodegen — ${srcJsonPath} does not exist`;
      }
      const srcCfg = JSON.parse(readFileSync(srcJsonPath, 'utf-8'));
      const compilers = srcCfg.compilers;
      if (!Array.isArray(compilers) || compilers.length !== 1 || compilers[0] !== 'go') {
        return `${entry.fixture}: go-only-nocodegen claims source.json compilers === ["go"], got ${JSON.stringify(compilers)}`;
      }
      return null;
    }
    case 'sdk-corner': {
      if (typeof cb.reason !== 'string' || cb.reason.trim().length === 0) {
        return `${entry.fixture}: sdk-corner requires a non-empty "reason" field`;
      }
      return null;
    }
    default:
      return `${entry.fixture}: unknown coveredBy.kind "${cb.kind}"`;
  }
}

describe('ledger honesty — coveredBy claims must be literally true', () => {
  it("every coverage-ledger.json entry's coveredBy claim is verifiably true", () => {
    const entries = loadLedger();
    const failures = entries.map(verifyClaim).filter((f): f is string => f !== null);
    expect(failures, `false coverage claims:\n${failures.join('\n')}`).toEqual([]);
  });

  it('every coverage-ledger.json entry has a known cause, a reason, and a unique fixture', () => {
    const entries = loadLedger();
    const failures: string[] = [];
    const seen = new Set<string>();
    for (const e of entries) {
      if (typeof e.fixture !== 'string' || e.fixture.length === 0) {
        failures.push(`entry with missing/empty "fixture": ${JSON.stringify(e)}`);
        continue;
      }
      if (seen.has(e.fixture)) failures.push(`${e.fixture}: duplicate ledger entry`);
      seen.add(e.fixture);
      if (typeof e.cause !== 'string' || !CAUSES.has(e.cause)) {
        failures.push(
          `${e.fixture}: unknown cause ${JSON.stringify(e.cause)} — must be one of ${[...CAUSES].join(', ')}`,
        );
      }
      if (typeof e.reason !== 'string' || e.reason.trim().length === 0) {
        failures.push(`${e.fixture}: missing/empty "reason"`);
      }
    }
    expect(failures, `malformed ledger entries:\n${failures.join('\n')}`).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// ">=1 accept and >=1 reject" — enforced in code, not just documented.
// ---------------------------------------------------------------------------

interface SpendSpec {
  expect: 'accept' | 'reject';
  [key: string]: unknown;
}
interface Spec {
  fixture?: string;
  acceptOnly?: boolean;
  spends: SpendSpec[];
}

function checkAcceptReject(dir: string, files: string[]): string[] {
  const failures: string[] = [];
  for (const f of files) {
    const spec: Spec = JSON.parse(readFileSync(join(dir, f), 'utf-8'));
    const spends = spec.spends ?? [];
    const accepts = spends.filter((s) => s.expect === 'accept').length;
    const rejects = spends.filter((s) => s.expect === 'reject').length;
    if (accepts === 0) failures.push(`${f}: zero accept spends`);
    if (rejects === 0 && spec.acceptOnly !== true) {
      failures.push(`${f}: zero reject spends and no "acceptOnly": true opt-out`);
    }
    if (rejects > 0 && spec.acceptOnly === true) {
      failures.push(`${f}: has ${rejects} reject spend(s) but "acceptOnly": true is set — stale opt-out`);
    }
  }
  return failures;
}

const NON_SPEC_JSON = new Set([LEDGER_FILE]);

describe('ledger honesty — every spend spec has >=1 accept and >=1 reject, or an explicit opt-out', () => {
  it('witnesses/*.json (mock-crypto differential oracle specs)', () => {
    const files = readdirSync(__dirname).filter(
      (f) => f.endsWith('.json') && !NON_SPEC_JSON.has(f),
    );
    const failures = checkAcceptReject(__dirname, files);
    expect(failures, failures.join('\n')).toEqual([]);
  });

  it('witnesses/real-crypto/*.json (real @bsv/sdk Spend specs)', () => {
    const dir = join(__dirname, 'real-crypto');
    const files = readdirSync(dir).filter((f) => f.endsWith('.json'));
    const failures = checkAcceptReject(dir, files);
    expect(failures, failures.join('\n')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Stateful accept ⇒ "expectedState" pin (Phase B / TG-002, PALMER-1 class).
//
// Accept/reject alone cannot catch a stateful spend whose script is accepted
// but whose post-spend state is silently wrong — that is exactly the PALMER-1
// shape (branch-merged locals producing a script the guard accepts, over the
// wrong continuation state). `real-crypto-execution.test.ts` already enforces
// this at execution time (`runStatefulSpend`'s caller throws if a stateful
// accept spend has neither "expectedState" nor "noStateCheck"); this block
// makes the same claim statically greppable without running the harness, per
// design principle P5 ("machine-check claims").
//
// Exception convention: reuses the harness's own opt-out
// (`noStateCheck: true` + a non-empty "note" explaining the burn/terminal
// state) rather than inventing a parallel "terminal"/"terminalReason" pair —
// one exception mechanism, not two that can drift apart.
// ---------------------------------------------------------------------------

interface StatefulSpendSpec {
  method?: string;
  expect: 'accept' | 'reject';
  tamperOutput?: boolean;
  expectedState?: Record<string, unknown> | null;
  noStateCheck?: boolean;
  note?: string;
  issue?: string;
  [key: string]: unknown;
}
interface StatefulSpec {
  fixture?: string;
  kind?: string;
  spends: StatefulSpendSpec[];
}

/** Closed vocabulary for `real-crypto/*.json`'s top-level "kind" — the exact
 * two values `real-crypto-execution.test.ts` branches on (`=== 'stateless-signed'`
 * vs. its `else`). A missing/misspelled "kind" must fail loudly here rather
 * than silently falling into the runtime harness's `else` (= "stateful") while
 * being invisible to this static gate (audit P2-1). */
const SPEC_KINDS = new Set(['stateful', 'stateless-signed']);

function checkExpectedStatePins(
  dir: string,
  files: string[],
): { failures: string[]; noStateCheckOptOuts: number } {
  const failures: string[] = [];
  let noStateCheckOptOuts = 0;
  for (const f of files) {
    const spec: StatefulSpec = JSON.parse(readFileSync(join(dir, f), 'utf-8'));
    if (!SPEC_KINDS.has(spec.kind as string)) {
      failures.push(
        `${f}: unknown spec "kind" ${JSON.stringify(spec.kind)} — must be one of ` +
          `${[...SPEC_KINDS].join(', ')}`,
      );
      continue;
    }
    // Mirror real-crypto-execution.test.ts's exact runtime branch
    // (`if (spec.kind === 'stateless-signed') { ... } else { /* stateful */ }`,
    // real-crypto-execution.test.ts:198) as its COMPLEMENT, not as an
    // `=== 'stateful'` check — the two must never be able to silently
    // diverge on what "stateful" means (audit P2-1).
    if (spec.kind === 'stateless-signed') continue;
    for (const s of spec.spends ?? []) {
      // A tampered continuation output must be a NEAR-MISS, never a claimed
      // accept — `tamperOutput: true` deliberately corrupts output 0
      // (real-crypto-execution.ts:tamperOutput handling), and the runtime
      // harness never populates `continuationState` for one, so an
      // `{"expect": "accept", "tamperOutput": true}` spend would assert that
      // a CORRUPTED continuation validates, with no state pin at all — a
      // silent hole in the exact guarantee this block exists to enforce
      // (audit P2-2).
      if (s.tamperOutput && s.expect !== 'reject') {
        failures.push(
          `${f}: ${spec.fixture}.${s.method} sets "tamperOutput": true with "expect": "${s.expect}" ` +
            `— a tampered continuation output must be asserted as a reject`,
        );
        continue;
      }
      // Mirror real-crypto-execution.test.ts's exact gate condition
      // (`s.expect === 'accept' && !s.tamperOutput`) so the static claim here
      // and the runtime enforcement there can never silently diverge.
      if (s.expect !== 'accept' || s.tamperOutput) continue;
      const hasState =
        s.expectedState !== undefined &&
        s.expectedState !== null &&
        typeof s.expectedState === 'object' &&
        Object.keys(s.expectedState).length > 0;
      const optsOut = s.noStateCheck === true;
      if (hasState && optsOut) {
        failures.push(
          `${f}: ${spec.fixture}.${s.method} sets both "expectedState" and "noStateCheck": true — pick one`,
        );
        continue;
      }
      if (optsOut) {
        noStateCheckOptOuts++;
        if (typeof s.note !== 'string' || s.note.trim().length === 0) {
          failures.push(
            `${f}: ${spec.fixture}.${s.method} sets "noStateCheck": true but has no non-empty "note" ` +
              `explaining why — a silent opt-out is not an honest one`,
          );
        }
        // Mandatory "issue" field, same precedent as coverage-ledger.json's
        // "UNCOVERED" kind above: a free opt-out with no residual accounting
        // is exactly the hole this block exists to keep loud (audit P2-3).
        if (typeof s.issue !== 'string' || s.issue.trim().length === 0) {
          failures.push(
            `${f}: ${spec.fixture}.${s.method} sets "noStateCheck": true but has no non-empty "issue" ` +
              `field describing the follow-up`,
          );
        }
        continue;
      }
      if (!hasState) {
        failures.push(
          `${f}: ${spec.fixture}.${s.method} is a stateful accept spend with no non-empty ` +
            `"expectedState" and no "noStateCheck": true opt-out — accept alone does not prove ` +
            `correct post-state (PALMER-1 class)`,
        );
      }
    }
  }
  return { failures, noStateCheckOptOuts };
}

describe('ledger honesty — every stateful accept spend pins expectedState (Phase B / PALMER-1)', () => {
  it('witnesses/real-crypto/*.json stateful accepts require "expectedState" or an explicit "noStateCheck" opt-out', () => {
    const dir = join(__dirname, 'real-crypto');
    const files = readdirSync(dir).filter((f) => f.endsWith('.json'));
    const { failures } = checkExpectedStatePins(dir, files);
    expect(failures, failures.join('\n')).toEqual([]);
  });

  // "noStateCheck" is an opt-OUT of the PALMER-1 state-value check, not a
  // free pass — nothing uses it today. Pinning the count at 0 turns the
  // first use into a deliberate, reviewable diff instead of a silent
  // accumulation of un-pinned stateful accepts (audit P2-3).
  it('"noStateCheck" opt-outs must not grow silently', () => {
    const dir = join(__dirname, 'real-crypto');
    const files = readdirSync(dir).filter((f) => f.endsWith('.json'));
    const { noStateCheckOptOuts } = checkExpectedStatePins(dir, files);
    expect(noStateCheckOptOuts, 'noStateCheck opt-outs must not grow').toBe(0);
  });
});
