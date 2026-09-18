import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = join(__dirname, '..', 'tests');
const REAL_CRYPTO_DIR = join(__dirname, 'real-crypto');

const NON_SPEC_JSON = new Set(['coverage-ledger.json']);

it('every conformance fixture is witnessed, real-crypto-executed, or in the coverage ledger', () => {
  const fixtures = readdirSync(TESTS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name);

  // Plain differential witnesses (mock-crypto source-vs-script agreement).
  const witnessed = new Set(
    readdirSync(__dirname)
      .filter((f) => f.endsWith('.json') && !NON_SPEC_JSON.has(f))
      .map((f) => f.replace(/\.json$/, '')),
  );

  // Real-crypto execution specs (real secp256k1 on @bsv/sdk Spend). Every one
  // of these is actually EXECUTED by real-crypto-execution.test.ts, so it
  // counts as covered — no silent caps.
  const realCryptoExecuted = new Set(
    readdirSync(REAL_CRYPTO_DIR)
      .filter((f) => f.endsWith('.json'))
      .map((f) => f.replace(/\.json$/, '')),
  );

  // A coverage-ledger entry only counts as COVERAGE if its `coveredBy` claim
  // names a real engine. `coveredBy.kind === "UNCOVERED"` is an honest
  // admission that nothing executes the fixture — coverage-claims.test.ts
  // verifies every OTHER kind's claim is literally true, but "UNCOVERED"
  // fixtures must still surface here as uncovered so the hole cannot hide
  // behind list membership (audit findings #P0-1, #11, #14, #24).
  type LedgerEntry = { fixture: string; cause?: string; coveredBy?: { kind: string } };
  const isCovered = (e: LedgerEntry) => e.coveredBy?.kind !== 'UNCOVERED';

  const ledgerEntries = JSON.parse(readFileSync(join(__dirname, 'coverage-ledger.json'), 'utf-8'))
    .entries as LedgerEntry[];

  // Used for the "uncovered" computation below: UNCOVERED-kind entries do
  // NOT count as coverage, so their fixture is excluded here on purpose.
  const ledgerCovered = new Set(ledgerEntries.filter(isCovered).map((e) => e.fixture));

  // Used for the stray-fixture-name typo guard below: ALL listed entries
  // (including honest UNCOVERED ones) must still name a real fixture.
  const ledgerAll = new Set(ledgerEntries.map((e) => e.fixture));

  const uncovered = fixtures.filter(
    (f) => !witnessed.has(f) && !realCryptoExecuted.has(f) && !ledgerCovered.has(f),
  );
  expect(
    uncovered,
    `fixtures with no witness/execution and no exemption (includes fixtures whose coverage-ledger.json entry is honestly marked coveredBy.kind "UNCOVERED" — see that file for the follow-up issue): ${uncovered.join(', ')}`,
  ).toEqual([]);

  // Guard against typos: an exemption naming a fixture that does not exist.
  const known = new Set(fixtures);
  const strayLedger = [...ledgerAll].filter((f) => !known.has(f));
  const strayRealCrypto = [...realCryptoExecuted].filter((f) => !known.has(f));
  expect(
    strayLedger,
    `coverage-ledger.json lists unknown fixtures: ${strayLedger.join(', ')}`,
  ).toEqual([]);
  expect(
    strayRealCrypto,
    `real-crypto specs name unknown fixtures: ${strayRealCrypto.join(', ')}`,
  ).toEqual([]);

  // Honesty guard: a fixture that is executed for real MUST NOT also sit in the
  // coverage ledger (a stale "routed out" claim). This is what keeps the ledger
  // from silently over-claiming coverage.
  const doubleListed = [...realCryptoExecuted].filter((f) => ledgerAll.has(f));
  expect(
    doubleListed,
    `real-crypto-executed fixtures still listed in coverage-ledger.json (remove them): ${doubleListed.join(', ')}`,
  ).toEqual([]);

  // R-205: the same guard for the OTHER pair of sets.
  //
  // The check above covers real-crypto specs and missed witnesses entirely, so
  // `oracle-price` sat in the ledger as "crypto-witness-infeasible — Rabin
  // witness is not secp256k1" for months after `witnesses/oracle-price.json`
  // was added on 2026-08-28. The ledger UNDERSTATED coverage there, which is
  // the benign direction — but a guard that only checks one of two pairs
  // cannot tell which direction it is missing, and the dangerous direction is
  // the same shape.
  const witnessedAndLedgered = [...witnessed].filter((f) => ledgerAll.has(f));
  expect(
    witnessedAndLedgered,
    `fixtures with a witness in conformance/witnesses/ are still listed in ` +
      `coverage-ledger.json as needing an exemption (remove them): ${witnessedAndLedgered.join(', ')}`,
  ).toEqual([]);
});

// ---------------------------------------------------------------------------
// Phase G / TG-005 / deep-review C24 — the residual UNEXECUTED-GOLDEN set.
//
// `completeness.test.ts` above proves every fixture is *accounted for*. It does
// NOT prove every fixture is *executed*: two `coveredBy` kinds are honest
// admissions that nothing runs the bytes —
//
//   codegen-golden      byte-golden only, executed by no engine
//   go-only-nocodegen   compilers:["go"] proof-system fixture, single-tier so
//                       there is not even a cross-tier agreement signal
//
// That set is the BUG-101 exposure surface: seven tiers can agree on a wrong
// answer indefinitely when nothing ever executes the result (BLAKE3 did exactly
// that until a real KAT ran). It was tracked only in README prose, which meant
// a new fixture could join it silently — the count in the README said 15 while
// the truth was 8, for months.
//
// Two gates, both enforced here rather than described:
//
//   G1  the set may SHRINK freely and may not GROW. MAX_UNEXECUTED_GOLDENS is a
//       committed ceiling; adding a residual fails CI until someone raises the
//       ceiling deliberately, which is the reviewable act.
//   G3  every member carries an explicit, DATED close plan. "We know about it"
//       is not a residual policy; "here is the specific test that would close
//       it, and here is why it does not exist yet" is.
//
// Deliberately NOT enforced here: that a close plan is *good*. That is a review
// judgement. What is enforced is that one exists, is dated, and is not empty —
// so a residual cannot sit unexamined behind a `kind` string.
// ---------------------------------------------------------------------------

/** `coveredBy.kind` values that mean "nothing executes this fixture's bytes". */
const RESIDUAL_KINDS = new Set(['codegen-golden', 'go-only-nocodegen']);

/**
 * Committed ceiling on the residual set. LOWER it when a fixture is genuinely
 * executed; raising it means the repo knowingly took on more unexecuted
 * surface, and that should be a visible, argued diff rather than a side effect.
 *
 * 2026-08-06: 8 -> 6. `post-quantum-wallet` and `sphincs-wallet` moved to
 * `kind: "integration"` — integration/go/wots_test.go and slhdsa_test.go
 * deploy AND SPEND those fixtures' own sources on a live regtest node with real
 * WOTS+ / SLH-DSA signatures plus reject legs, and both compiles were verified
 * byte-identical to the fixtures' expected-script.hex (19,594 and 188,609
 * bytes, both fold modes). That is new execution being recognised, not a
 * relabel — the README's "the four *-wallet entries only deploy" was stale.
 *
 * 2026-08-07: 6 -> 3. Merge arithmetic, not a new decision. The 6 above was
 * committed on fix/testing-gap-remediation, which removed 2 of the original 8;
 * fix/ec-complete-formulas independently removed 3 more (`ec-unit`,
 * `p256-primitives`, `p384-primitives`), which 03f50d48 gave real-crypto
 * execution specs under witnesses/real-crypto/ and which the honesty guard in
 * the completeness test above then REQUIRES to be dropped from the ledger.
 * Neither branch could see the other's removals, so the merged residual set is
 * 8 - 2 - 3 = 3 while the constant still read 6. Lowering it restores the
 * no-slack invariant; the residual set itself did not grow.
 */
const MAX_UNEXECUTED_GOLDENS = 3;

interface ClosePlan {
  date?: unknown;
  plan?: unknown;
}
interface ResidualEntry {
  fixture: string;
  closePlan?: ClosePlan;
  coveredBy?: { kind?: string };
}

function loadEntries(): ResidualEntry[] {
  return JSON.parse(readFileSync(join(__dirname, 'coverage-ledger.json'), 'utf-8'))
    .entries as ResidualEntry[];
}

const residualsOf = (entries: ResidualEntry[]): ResidualEntry[] =>
  entries.filter((e) => RESIDUAL_KINDS.has(e.coveredBy?.kind ?? ''));

/** ISO calendar date, so "soon" or "Q3" cannot pass as a date. */
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

function checkClosePlans(entries: ResidualEntry[]): string[] {
  const failures: string[] = [];
  for (const e of residualsOf(entries)) {
    const cp = e.closePlan;
    if (!cp || typeof cp !== 'object') {
      failures.push(
        `${e.fixture}: coveredBy.kind "${e.coveredBy?.kind}" means nothing executes this fixture, ` +
          `but it carries no "closePlan". A residual needs a named next step, not just a label.`,
      );
      continue;
    }
    if (typeof cp.date !== 'string' || !ISO_DATE.test(cp.date)) {
      failures.push(
        `${e.fixture}: closePlan.date ${JSON.stringify(cp.date)} — must be an ISO YYYY-MM-DD date, ` +
          `so a stale plan is visibly stale.`,
      );
    }
    if (typeof cp.plan !== 'string' || cp.plan.trim().length === 0) {
      failures.push(`${e.fixture}: closePlan.plan must be a non-empty description of the close`);
    }
  }
  return failures;
}

describe('Phase G — residual unexecuted goldens stay bounded and accounted for', () => {
  it('G1: the residual set does not grow past the committed ceiling', () => {
    const residuals = residualsOf(loadEntries()).map((e) => e.fixture);
    expect(
      residuals.length,
      `${residuals.length} fixture(s) are byte-golden-only with no execution behind them ` +
        `(${residuals.join(', ')}), above the committed ceiling of ${MAX_UNEXECUTED_GOLDENS}. ` +
        `Either execute the new one (KAT against compiled bytes, a real-crypto witness, or an on-chain spend) ` +
        `or raise MAX_UNEXECUTED_GOLDENS deliberately with a reason. Do NOT close an item by relabelling its ` +
        `coveredBy.kind — a stronger-sounding label with no new execution is worse than an honest residual.`,
    ).toBeLessThanOrEqual(MAX_UNEXECUTED_GOLDENS);
  });

  it('G3: every residual carries an explicit, dated close plan', () => {
    const failures = checkClosePlans(loadEntries());
    expect(failures, `residuals without a usable close plan:\n${failures.join('\n')}`).toEqual([]);
  });

  it('the ceiling is not slack — it equals the residual count, so the next addition fails', () => {
    // A ceiling with headroom silently absorbs the next residual. Keeping it
    // exact is what makes G1 a ratchet rather than a budget.
    expect(residualsOf(loadEntries()).length).toBe(MAX_UNEXECUTED_GOLDENS);
  });
});

// ---------------------------------------------------------------------------
// RED-PROOFS — both Phase G gates, shown failing on corrupted in-memory copies.
// Nothing on disk is modified.
// ---------------------------------------------------------------------------

describe('RED-PROOF: Phase G gates fire', () => {
  const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

  it('G1: one more codegen-golden entry breaks the ceiling', () => {
    const entries = clone(loadEntries());
    expect(residualsOf(entries).length).toBeLessThanOrEqual(MAX_UNEXECUTED_GOLDENS);
    entries.push({
      fixture: 'some-new-unexecuted-fixture',
      closePlan: { date: '2026-08-06', plan: 'x' },
      coveredBy: { kind: 'codegen-golden' },
    });
    expect(residualsOf(entries).length).toBeGreaterThan(MAX_UNEXECUTED_GOLDENS);
  });

  it('G1: a fixture DOWNGRADED from an executed kind back to codegen-golden also breaks it', () => {
    // The subtler regression: no new fixture, but an existing execution claim
    // is withdrawn. A count-only ratchet catches this too.
    const entries = clone(loadEntries());
    const executed = entries.find((e) => e.coveredBy?.kind === 'integration');
    expect(executed, 'expected at least one integration-kind entry').toBeDefined();
    executed!.coveredBy = { kind: 'codegen-golden' };
    expect(residualsOf(entries).length).toBeGreaterThan(MAX_UNEXECUTED_GOLDENS);
  });

  it('G3: a residual with no closePlan fails', () => {
    const entries = clone(loadEntries());
    expect(checkClosePlans(entries)).toEqual([]);
    delete residualsOf(entries)[0]!.closePlan;
    expect(checkClosePlans(entries).join('\n')).toMatch(/carries no "closePlan"/);
  });

  it('G3: a closePlan with a vague date fails', () => {
    const entries = clone(loadEntries());
    residualsOf(entries)[0]!.closePlan = { date: 'soon', plan: 'we will get to it' };
    expect(checkClosePlans(entries).join('\n')).toMatch(/must be an ISO YYYY-MM-DD date/);
  });

  it('G3: a closePlan with an empty plan fails', () => {
    const entries = clone(loadEntries());
    residualsOf(entries)[0]!.closePlan = { date: '2026-08-06', plan: '   ' };
    expect(checkClosePlans(entries).join('\n')).toMatch(/non-empty description/);
  });
});
