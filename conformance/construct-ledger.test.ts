/**
 * Construct ledger gate — reviewer point #2 / TG-003 / TG-015 / plan Phase D0.
 *
 * Coverage in this repo has always been counted in FIXTURES. Nothing tracked
 * which fund-critical *constructs* — language shapes and wire value classes —
 * are actually exercised. Both 2026-08 fund-safety bugs were construct holes,
 * not fixture holes:
 *
 *   - branch-merged locals with >=2 merged locals (an `if` carries ONE value,
 *     so post-branch references kept naming the dead pre-branch binding and
 *     stack lowering registered one slot for N physical results — permanently
 *     unspendable locking scripts from idiomatic source);
 *   - a 1-byte ByteString state value in the OP_N range, which the SDKs framed
 *     as OP_1..OP_16 while all seven compilers framed it `<len><data>`.
 *
 * Both would have shown up here as EMPTY CELLS. That is the whole point of the
 * file: `construct-ledger.json` is a matrix of fund-critical constructs, and a
 * row is either backed by evidence that exists on disk, or it is an honest,
 * loud `UNCOVERED` with a close plan. There is no third state.
 *
 * This test is deliberately built in the style of
 * `witnesses/coverage-claims.test.ts`: claims are MACHINE-CHECKED, never
 * trusted as prose. Free-text `description` / `issue` are for humans; the
 * `coveredBy[].path` entries are the evidence, and they must exist.
 *
 * Gates, one `it` each so a failure names the specific broken invariant:
 *
 *   1. coveredBy XOR UNCOVERED — never both, never neither.
 *   2. every `coveredBy[].path` exists on disk (repo-relative from repo root)
 *      AND is non-empty. Bare `existsSync` passed an empty file and a
 *      directory alike; "the path exists" is not "the evidence exists".
 *   3. the REQUIRED_CONSTRUCTS set below is hard-coded IN THIS FILE. A new
 *      fund-critical construct cannot be introduced without a ledger row,
 *      because adding its id here fails CI until the row exists.
 *   4. ids are unique; `category` / `severity` / `coveredBy[].kind` come from
 *      closed enums, so a typo cannot invent an unreviewed coverage axis.
 *   5. `kind` MATCHES THE SHAPE OF `path`. Enum membership alone let
 *      `{"kind":"real-crypto-witness","path":"conformance/README.md"}` pass
 *      every gate while the schema doc calls that "the strongest kind in this
 *      file". A `kind` is a claim about *what the evidence is*; KIND_SHAPE
 *      makes the claim checkable instead of decorative.
 *   6. ROUND-TRIP-ONLY EVIDENCE IS NOT COVERAGE (reviewer point #4). A file on
 *      the denylist below only ever asserts `deserialize(serialize(x)) === x`
 *      against its OWN inverse — it cannot detect a change that moves both
 *      sides together, which is exactly how the OP_N state-framing bug
 *      survived. Citing one as evidence is a hard failure.
 *   7. THE DENYLIST IS LIVE. Nothing used to assert the denylisted paths still
 *      existed, so a rename silently turned the denylist into a no-op — the
 *      exact decay mode the sibling wire-format gate defends against.
 *   8. THE REQUIRED SET CANNOT BE EDITED RED-TO-GREEN. There is no CODEOWNERS
 *      on this file, so a PR that trips gate 3 could simply delete the id it
 *      trips on. A committed floor (`MIN_REQUIRED_CONSTRUCTS`) that may only
 *      be raised, plus a bijection with the ledger's own row ids, makes
 *      shrinking the requirement a visibly deliberate diff.
 *
 * RED-PROOFS at the bottom: every gate above is shown FAILING on a
 * deliberately corrupted in-memory copy. A gate that has never been observed
 * to fail is a gate that has never been tested (the same reasoning
 * `conformance/sdk-vertical/vertical-pins.test.ts` applies to its pins).
 * Nothing on disk is modified.
 */
import { describe, it, expect } from 'vitest';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..');
const LEDGER_FILE = 'construct-ledger.json';
const LEDGER_PATH = join(__dirname, LEDGER_FILE);

interface CoveredBy {
  kind: string;
  path: string;
  note?: string;
}
interface LedgerRow {
  id?: unknown;
  category?: unknown;
  description?: unknown;
  severity?: unknown;
  coveredBy?: unknown;
  status?: unknown;
  issue?: unknown;
}

/** Closed enums. A value outside these is a typo, not a new axis. */
const CATEGORIES = new Set(['language', 'control-flow', 'wire', 'artifact']);
const SEVERITIES = new Set(['fund-critical', 'correctness']);
const KINDS = new Set([
  'conformance-fixture',
  'real-crypto-witness',
  'sdk-output',
  'vertical-pin',
  'negative-compile',
  'vm-unit',
]);

/**
 * The fund-critical construct set, hard-coded HERE rather than derived from the
 * ledger — deriving it from the ledger would make the gate vacuous (a deleted
 * row would delete its own requirement). Adding an id here is how a new
 * fund-critical construct is declared; CI stays red until the row is filled in
 * or honestly marked UNCOVERED.
 */
const REQUIRED_CONSTRUCTS = [
  // --- branch-merged locals (the 2026-08 miscompilation family) -----------
  'merge-locals-k1',
  'merge-locals-k2-asymmetric',
  'merge-locals-k2-both-arms',
  'merge-locals-k3',
  'merge-locals-nested-if',
  'merge-locals-nested-declared-results-inherited-slot',
  'loop-carried-locals-k2',
  'merge-locals-with-prop-updates',
  'cond-write-multi-property',
  'if-outputs-and-merge-locals',
  // --- wire value classes in the state section ----------------------------
  // State framing has THREE rules, not one (packages/runar-sdk/src/state.ts
  // `encodeStateValue`): bigint -> raw NUM2BIN-LE8; bool -> ONE RAW BYTE with
  // no push header; PubKey/Addr/Ripemd160/Sha256/Point -> RAW FIXED BYTES with
  // no push header; ByteString -> `<len><data>`. Every one of those is a
  // distinct branch that can shift every LATER field's offset when it is
  // wrong, and state.ts:327-335 records that the `bool` branch already shipped
  // broken once (a real boolean state field fell through to the push-data
  // default). Tracking only the ByteString and bigint classes left two of the
  // four framing rules with no row at all.
  'state-bytestring-1byte-op-n',
  'state-bytestring-empty',
  'state-bytestring-0x00',
  'state-bytestring-multibyte',
  'state-bigint-edges',
  'state-bool',
  'state-raw-fixed-bytes',
  // --- artifact-level layout ----------------------------------------------
  'constructor-slots-bytestring-op-n',
  'codeseparator-indices-stateful',
  // Continuation output ORDERING / index. The ledger's own `_doc` names two
  // fund-loss faces; a wrong output order desynchronises `hashOutputs` and is
  // the second one. It had no row.
  'continuation-output-ordering',
];

/**
 * Committed floor for REQUIRED_CONSTRUCTS. This file has no CODEOWNERS, so
 * nothing stopped a PR that trips gate 3 from deleting the id it trips on and
 * going green in the same diff. Raising this number is how a construct family
 * is locked in; LOWERING it is the deliberate, reviewable act it should be.
 * Same spirit as the repo's `lint-no-silent-skips` job.
 */
const MIN_REQUIRED_CONSTRUCTS = 20;

/**
 * Files that ONLY prove an implementation is its own inverse. Verified by
 * reading each one — not inferred from the filename:
 *
 *   - `state.test.ts` — every ByteString case and every bigint SERIALIZE case
 *     is `deserializeState(serializeState(x)) === x`. Its only absolute pins
 *     are the boolean byte and the decode-direction `decodeNum2Bin` block, so
 *     it is round-trip-only for every construct this ledger tracks.
 *   - `ctor-bytestring-minimaldata-roundtrip.test.ts` — `encodeArg` vs
 *     `extractConstructorArgs`, same implementation, no expected bytes.
 *   - the SIX per-tier `c9_s1_minimaldata_roundtrip` siblings — the same
 *     round-trip replayed in Go, Rust, Python, Zig, Ruby AND Java. (The Java
 *     analogue is named `MinimalDataRoundTripTest.java` rather than
 *     `c9_s1_...`; it was omitted here until 2026-08-06, and the comment
 *     simultaneously said "six" while listing five languages.) Seven tiers
 *     agreeing with their own inverses is still not an absolute pin.
 *
 * Java is a MIXED file and is denylisted deliberately: its C9 state-path and
 * S1 ctor-path blocks are pure round-trips, but
 * `encodePushDataMatchesCompilerEncodePushBytesHex` IS a real absolute pin
 * (`encodePushData("00") === "0100"`, `("05") === "55"`, …). This ledger cites
 * evidence at FILE granularity, so a citation of that path cannot say which
 * half it means. Denylisted at the path level; if the Java absolute pin is
 * ever needed as ledger evidence, split it into its own file first.
 *
 * NOT denylisted, on purpose — the per-tier state suites that look like
 * siblings but are not round-trip-ONLY. Each carries literal expected bytes,
 * and each is named as the absolute-pin counterpart in the header comment of
 * its own `c9_s1_minimaldata_roundtrip` sibling:
 *   - `packages/runar-rs/tests/state_push_framing.rs`   (`encode("00")=="0100"`, …)
 *   - `packages/runar-py/tests/test_sdk_state.py`       (`encode_push_data('00')=='0100'`, …)
 *   - `packages/runar-rb/spec/sdk/state_spec.rb`        (`encode_push_data('00')=='0100'`, …)
 *   - `packages/runar-zig/src/sdk_state.zig`
 * Denylisting those would delete real evidence, which is the opposite failure.
 *
 * A construct backed ONLY by a denylisted file has no coverage. Cite the
 * absolute pin instead (`encode-push-data-minimaldata.test.ts`,
 * `state-push-framing-vm.test.ts`, an sdk-output golden, an sdk-vertical case,
 * or a real-crypto witness with `expectedState`).
 */
const ROUND_TRIP_ONLY_PATHS = new Set([
  'packages/runar-sdk/src/__tests__/state.test.ts',
  'packages/runar-sdk/src/__tests__/ctor-bytestring-minimaldata-roundtrip.test.ts',
  'packages/runar-go/sdk_c9_s1_minimaldata_roundtrip_test.go',
  'packages/runar-rs/tests/c9_s1_minimaldata_roundtrip.rs',
  'packages/runar-py/tests/test_c9_s1_minimaldata_roundtrip.py',
  'packages/runar-zig/src/sdk_c9_s1_minimaldata_roundtrip_test.zig',
  'packages/runar-rb/spec/sdk/c9_s1_minimaldata_roundtrip_spec.rb',
  'packages/runar-java/src/test/java/runar/lang/sdk/MinimalDataRoundTripTest.java',
]);

// ---------------------------------------------------------------------------
// Per-kind path SHAPE rules (gate 5)
// ---------------------------------------------------------------------------

const isFile = (abs: string) => existsSync(abs) && statSync(abs).isFile();
const isDir = (abs: string) => existsSync(abs) && statSync(abs).isDirectory();

/** Returns null when the (kind, path) pair is shaped correctly, else why not. */
type ShapeRule = (abs: string, rel: string) => string | null;

const KIND_SHAPE: Record<string, ShapeRule> = {
  // Executed by real-crypto-execution.test.ts, which reads exactly this
  // directory. A path outside it is not executed by anything.
  'real-crypto-witness': (abs, rel) =>
    /^conformance\/witnesses\/real-crypto\/[^/]+\.json$/.test(rel) && isFile(abs)
      ? null
      : 'must be a conformance/witnesses/real-crypto/<fixture>.json spec file — those are the only files real-crypto-execution.test.ts executes',

  // The absolute byte golden all seven SDK tools must reproduce lives in the
  // case directory; a citation without that file pins nothing.
  'sdk-output': (abs, rel) =>
    /^conformance\/sdk-output\/tests\/[^/]+$/.test(rel) &&
    isDir(abs) &&
    isFile(join(abs, 'expected-locking.hex'))
      ? null
      : 'must be a conformance/sdk-output/tests/<name>/ directory containing expected-locking.hex',

  // Two legal shapes, exactly as the schema doc in construct-ledger.json says:
  // the cross-tier golden directory, or its differential-oracle spend spec.
  'conformance-fixture': (abs, rel) => {
    if (/^conformance\/tests\/[^/]+$/.test(rel) && isDir(abs) && isFile(join(abs, 'source.json'))) {
      return null;
    }
    if (
      /^conformance\/witnesses\/[^/]+\.json$/.test(rel) &&
      rel !== 'conformance/witnesses/coverage-ledger.json' &&
      isFile(abs)
    ) {
      return null;
    }
    return 'must be a conformance/tests/<fixture>/ directory containing source.json, or its conformance/witnesses/<fixture>.json differential-oracle spend spec';
  },

  // A vertical pin is either a compiler<->SDK TEST FILE, or an
  // sdk-vertical case directory — the case dir IS the pin (its
  // expected-locking.hex is what all seven SDK tiers must reproduce, and
  // vertical-pins.test.ts re-derives it from the artifact with an
  // implementation that imports nothing from packages/**). Citing the case
  // directory rather than only the test file is what makes a renamed or
  // deleted case turn this row RED instead of silently vacuous.
  'vertical-pin': (abs, rel) => {
    if (
      /^conformance\/sdk-vertical\/cases\/[^/]+$/.test(rel) &&
      isDir(abs) &&
      isFile(join(abs, 'expected-locking.hex'))
    ) {
      return null;
    }
    if (isFile(abs)) return null;
    return 'must be a compiler<->SDK test FILE, or a conformance/sdk-vertical/cases/<name>/ directory containing expected-locking.hex';
  },

  'negative-compile': (abs) =>
    isFile(abs) ? null : 'must be a test FILE that asserts the rejected compile and its diagnostic',
  'vm-unit': (abs) => (isFile(abs) ? null : 'must be a test FILE'),
};

// ---------------------------------------------------------------------------
// Pure checkers — every gate is a function over its inputs so the RED-PROOFs at
// the bottom can feed it a corrupted copy without touching disk.
// ---------------------------------------------------------------------------

function loadLedger(): LedgerRow[] {
  const doc = JSON.parse(readFileSync(LEDGER_PATH, 'utf-8'));
  return doc.constructs as LedgerRow[];
}

/** `coveredBy` entries that are well-formed enough to have a path checked. */
function coveredByOf(row: LedgerRow): CoveredBy[] {
  return Array.isArray(row.coveredBy) ? (row.coveredBy as CoveredBy[]) : [];
}

/** Non-empty = a file with bytes, or a directory with at least one entry.
 *  `existsSync` alone waves through an empty file and a stray directory. */
function isNonEmpty(abs: string): boolean {
  const st = statSync(abs);
  if (st.isDirectory()) return readdirSync(abs).length > 0;
  return st.size > 0;
}

function checkCellShape(rows: LedgerRow[]): string[] {
  const failures: string[] = [];
  for (const row of rows) {
    const id = String(row.id);
    const covered = Array.isArray(row.coveredBy) && row.coveredBy.length > 0;
    const uncovered = row.status === 'UNCOVERED';

    if (covered && uncovered) {
      failures.push(
        `${id}: has BOTH a non-empty coveredBy and status:"UNCOVERED" — an UNCOVERED row must carry no evidence, or drop the status`,
      );
    }
    if (!covered && !uncovered) {
      failures.push(
        `${id}: has neither a non-empty coveredBy nor status:"UNCOVERED" — an empty cell must be declared, not left blank`,
      );
    }
    if (uncovered && (typeof row.issue !== 'string' || row.issue.trim().length === 0)) {
      failures.push(
        `${id}: status:"UNCOVERED" requires a non-empty "issue" (a tracking ref or a dated close plan)`,
      );
    }
    if (!uncovered && row.issue !== undefined) {
      failures.push(`${id}: has an "issue" but is not UNCOVERED — put the note in coveredBy[].note`);
    }
  }
  return failures;
}

function checkPathsExist(rows: LedgerRow[], root: string = REPO_ROOT): string[] {
  const failures: string[] = [];
  for (const row of rows) {
    const id = String(row.id);
    for (const cb of coveredByOf(row)) {
      if (typeof cb.path !== 'string' || cb.path.trim().length === 0) {
        failures.push(`${id}: coveredBy entry with a missing/empty "path": ${JSON.stringify(cb)}`);
        continue;
      }
      if (cb.path.startsWith('/')) {
        failures.push(`${id}: coveredBy path "${cb.path}" must be repo-relative, not absolute`);
        continue;
      }
      const abs = join(root, cb.path);
      if (!existsSync(abs)) {
        failures.push(
          `${id}: claims evidence at ${cb.path} — that path does not exist. Either the evidence was deleted/renamed (fix the ledger or restore it) or the claim was never true.`,
        );
        continue;
      }
      if (!isNonEmpty(abs)) {
        failures.push(
          `${id}: claims evidence at ${cb.path} — the path exists but is EMPTY. An empty file or empty directory is not evidence.`,
        );
      }
    }
  }
  return failures;
}

function checkKindMatchesPath(rows: LedgerRow[]): string[] {
  const failures: string[] = [];
  for (const row of rows) {
    const id = String(row.id);
    for (const cb of coveredByOf(row)) {
      if (typeof cb.kind !== 'string' || !KINDS.has(cb.kind)) continue; // gate 4's job
      if (typeof cb.path !== 'string' || cb.path.trim().length === 0 || cb.path.startsWith('/')) {
        continue; // gate 2's job
      }
      const abs = join(REPO_ROOT, cb.path);
      if (!existsSync(abs)) continue; // gate 2's job
      const why = KIND_SHAPE[cb.kind]!(abs, cb.path);
      if (why) {
        failures.push(`${id}: kind "${cb.kind}" claims ${cb.path}, but a "${cb.kind}" ${why}.`);
      }
    }
  }
  return failures;
}

function checkEnums(rows: LedgerRow[]): string[] {
  const failures: string[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    if (typeof row.id !== 'string' || row.id.trim().length === 0) {
      failures.push(`row with a missing/empty "id": ${JSON.stringify(row)}`);
      continue;
    }
    const id = row.id;
    if (seen.has(id)) failures.push(`${id}: duplicate construct id`);
    seen.add(id);

    if (typeof row.category !== 'string' || !CATEGORIES.has(row.category)) {
      failures.push(
        `${id}: category ${JSON.stringify(row.category)} — must be one of ${[...CATEGORIES].join(', ')}`,
      );
    }
    if (typeof row.severity !== 'string' || !SEVERITIES.has(row.severity)) {
      failures.push(
        `${id}: severity ${JSON.stringify(row.severity)} — must be one of ${[...SEVERITIES].join(', ')}`,
      );
    }
    if (typeof row.description !== 'string' || row.description.trim().length === 0) {
      failures.push(`${id}: missing/empty "description"`);
    }
    for (const cb of coveredByOf(row)) {
      if (typeof cb.kind !== 'string' || !KINDS.has(cb.kind)) {
        failures.push(
          `${id}: coveredBy kind ${JSON.stringify(cb.kind)} — must be one of ${[...KINDS].join(', ')}`,
        );
      }
    }
  }
  return failures;
}

function checkNoRoundTripOnly(rows: LedgerRow[], denylist: Set<string>): string[] {
  const failures: string[] = [];
  for (const row of rows) {
    for (const cb of coveredByOf(row)) {
      if (typeof cb.path === 'string' && denylist.has(cb.path)) {
        failures.push(
          `${String(row.id)}: cites ${cb.path}, which only proves the implementation is its own inverse. ` +
            `A round-trip cannot detect a change that moves encode and decode together — the exact shape of the ` +
            `OP_N state-framing bug. Cite an absolute byte pin, a cross-implementation pin, or mark the row UNCOVERED.`,
        );
      }
    }
  }
  return failures;
}

/** Gate 7 — a denylist entry that no longer names a real file is a no-op. */
function checkDenylistLiveness(denylist: Set<string>): string[] {
  const failures: string[] = [];
  for (const p of denylist) {
    const abs = join(REPO_ROOT, p);
    if (!existsSync(abs)) {
      failures.push(
        `ROUND_TRIP_ONLY_PATHS names ${p}, which does not exist. A renamed or deleted denylist entry ` +
          `silently stops denying anything — the round-trip file can then be cited as coverage with no gate ` +
          `firing. Re-point the entry at the file's new path, or delete it deliberately with a note saying why.`,
      );
      continue;
    }
    if (!isFile(abs)) {
      failures.push(`ROUND_TRIP_ONLY_PATHS names ${p}, which is not a file.`);
    }
  }
  return failures;
}

/** Gate 8 — the required set may grow freely and shrink only deliberately. */
function checkRequiredSetIntegrity(
  required: string[],
  rows: LedgerRow[],
  floor: number,
): string[] {
  const failures: string[] = [];

  const dupes = required.filter((id, i) => required.indexOf(id) !== i);
  if (dupes.length > 0) {
    failures.push(`REQUIRED_CONSTRUCTS has duplicate id(s): ${[...new Set(dupes)].join(', ')}`);
  }

  const uniq = new Set(required);
  if (uniq.size < floor) {
    failures.push(
      `REQUIRED_CONSTRUCTS has ${uniq.size} construct(s), below the committed floor of ${floor}. ` +
        `This file has no CODEOWNERS, so deleting an id is otherwise a same-PR way to turn gate 3 from red ` +
        `to green. Lowering MIN_REQUIRED_CONSTRUCTS must be its own reviewed decision with a reason.`,
    );
  }

  // The other direction of gate 3: a row may not exist without being required.
  // Without this, a construct can be quietly demoted by deleting its id from
  // REQUIRED_CONSTRUCTS while leaving the row in place, and nothing notices.
  const rowIds = rows
    .map((r) => r.id)
    .filter((id): id is string => typeof id === 'string' && id.trim().length > 0);
  const orphans = rowIds.filter((id) => !uniq.has(id));
  if (orphans.length > 0) {
    failures.push(
      `${LEDGER_FILE} has row(s) with no entry in REQUIRED_CONSTRUCTS: ${orphans.join(', ')}. ` +
        `The two must be the same set — otherwise a construct is silently demoted by deleting one line here ` +
        `while its row stays put, and gate 3 (which only checks required -> row) stays green.`,
    );
  }
  return failures;
}

// ---------------------------------------------------------------------------
// GREEN — the checked-in ledger
// ---------------------------------------------------------------------------

describe('construct ledger — fund-critical constructs are tracked, not assumed', () => {
  it('every row is either covered or an honest UNCOVERED — never both, never neither', () => {
    const failures = checkCellShape(loadLedger());
    expect(failures, `malformed coverage cells:\n${failures.join('\n')}`).toEqual([]);
  });

  it('every coveredBy[].path exists on disk and is non-empty', () => {
    const failures = checkPathsExist(loadLedger());
    expect(failures, `dangling evidence claims:\n${failures.join('\n')}`).toEqual([]);
  });

  it('every required fund-critical construct has a row', () => {
    const present = new Set(loadLedger().map((r) => String(r.id)));
    const missing = REQUIRED_CONSTRUCTS.filter((id) => !present.has(id));
    expect(
      missing,
      `construct(s) in REQUIRED_CONSTRUCTS with no row in ${LEDGER_FILE}:\n${missing.join('\n')}\n` +
        `Add a row with real evidence, or a status:"UNCOVERED" row with a close plan.`,
    ).toEqual([]);
  });

  it('ids are unique and category/severity/kind come from the closed enums', () => {
    const failures = checkEnums(loadLedger());
    expect(failures, `malformed ledger rows:\n${failures.join('\n')}`).toEqual([]);
  });

  it('every coveredBy[].kind matches the SHAPE of the path it claims', () => {
    const failures = checkKindMatchesPath(loadLedger());
    expect(failures, `kind/path mismatches:\n${failures.join('\n')}`).toEqual([]);
  });

  it('no row is backed by round-trip-only evidence', () => {
    const failures = checkNoRoundTripOnly(loadLedger(), ROUND_TRIP_ONLY_PATHS);
    expect(failures, `round-trip-only coverage claims:\n${failures.join('\n')}`).toEqual([]);
  });

  it('every ROUND_TRIP_ONLY_PATHS entry still names a real file (the denylist is live)', () => {
    const failures = checkDenylistLiveness(ROUND_TRIP_ONLY_PATHS);
    expect(failures, `dead denylist entries:\n${failures.join('\n')}`).toEqual([]);
  });

  it('REQUIRED_CONSTRUCTS cannot be shrunk red-to-green, and matches the ledger row ids exactly', () => {
    const failures = checkRequiredSetIntegrity(
      REQUIRED_CONSTRUCTS,
      loadLedger(),
      MIN_REQUIRED_CONSTRUCTS,
    );
    expect(failures, `required-set integrity:\n${failures.join('\n')}`).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// RED-PROOFS — each gate above, shown failing on a corrupted in-memory copy.
// Nothing on disk is modified.
// ---------------------------------------------------------------------------

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

/** A row known to be covered, for corruption. */
function firstCoveredRow(rows: LedgerRow[]): LedgerRow {
  const row = rows.find((r) => coveredByOf(r).length > 0);
  if (!row) throw new Error('no covered row in the ledger to corrupt');
  return row;
}

describe('RED-PROOF: gate 2 — an empty or missing evidence path', () => {
  it('a path that does not exist fails', () => {
    const rows = clone(loadLedger());
    expect(checkPathsExist(rows)).toEqual([]);
    coveredByOf(firstCoveredRow(rows))[0]!.path = 'packages/runar-sdk/src/__tests__/nope.test.ts';
    expect(checkPathsExist(rows).join('\n')).toMatch(/does not exist/);
  });

  it('a path that EXISTS but is empty fails — bare existsSync passed all three of these', () => {
    // Built in the OS temp dir, never in the repo: an empty file, an empty
    // directory, and a non-empty file, then the checker is pointed at that
    // root. Before this gate, all three were indistinguishable.
    const root = mkdtempSync(join(tmpdir(), 'runar-ledger-redproof-'));
    try {
      writeFileSync(join(root, 'empty.test.ts'), '');
      mkdirSync(join(root, 'empty-dir'));
      writeFileSync(join(root, 'real.test.ts'), 'it("x", () => {});\n');

      const rowFor = (p: string): LedgerRow[] => [
        {
          id: 'red-proof',
          category: 'wire',
          description: 'red proof',
          severity: 'fund-critical',
          coveredBy: [{ kind: 'vm-unit', path: p }],
        },
      ];

      expect(checkPathsExist(rowFor('real.test.ts'), root)).toEqual([]);
      expect(existsSync(join(root, 'empty.test.ts'))).toBe(true); // the old gate's whole check
      expect(checkPathsExist(rowFor('empty.test.ts'), root).join('\n')).toMatch(/is EMPTY/);
      expect(existsSync(join(root, 'empty-dir'))).toBe(true);
      expect(checkPathsExist(rowFor('empty-dir'), root).join('\n')).toMatch(/is EMPTY/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('RED-PROOF: gate 5 — kind does not match the shape of path', () => {
  it('a real-crypto-witness pointing at a doc fails (it used to pass every gate)', () => {
    const rows = clone(loadLedger());
    expect(checkKindMatchesPath(rows)).toEqual([]);
    const cb = coveredByOf(firstCoveredRow(rows))[0]!;
    cb.kind = 'real-crypto-witness';
    cb.path = 'conformance/README.md';
    const out = checkKindMatchesPath(rows).join('\n');
    expect(out).toMatch(/real-crypto-witness/);
    expect(out).toMatch(/conformance\/witnesses\/real-crypto/);
    // And prove the OLD gates would NOT have caught it: the path exists, is
    // non-empty, and the kind is a member of the closed enum.
    expect(checkPathsExist(rows)).toEqual([]);
    expect(checkEnums(rows)).toEqual([]);
  });

  it('an sdk-output claim on a directory with no expected-locking.hex fails', () => {
    const rows = clone(loadLedger());
    const cb = coveredByOf(firstCoveredRow(rows))[0]!;
    cb.kind = 'sdk-output';
    cb.path = 'conformance/sdk-output';
    expect(checkKindMatchesPath(rows).join('\n')).toMatch(/expected-locking\.hex/);
  });

  it('a conformance-fixture claim on a directory with no source.json fails', () => {
    const rows = clone(loadLedger());
    const cb = coveredByOf(firstCoveredRow(rows))[0]!;
    cb.kind = 'conformance-fixture';
    cb.path = 'conformance/tests';
    expect(checkKindMatchesPath(rows).join('\n')).toMatch(/source\.json/);
  });

  it('a vm-unit / negative-compile claim on a DIRECTORY fails', () => {
    const rows = clone(loadLedger());
    const cb = coveredByOf(firstCoveredRow(rows))[0]!;
    cb.kind = 'vm-unit';
    cb.path = 'packages/runar-sdk/src/__tests__';
    expect(checkKindMatchesPath(rows).join('\n')).toMatch(/must be a test FILE/);
  });
});

describe('RED-PROOF: gate 6/7 — the round-trip denylist', () => {
  it('citing a denylisted round-trip file fails', () => {
    const rows = clone(loadLedger());
    expect(checkNoRoundTripOnly(rows, ROUND_TRIP_ONLY_PATHS)).toEqual([]);
    coveredByOf(firstCoveredRow(rows))[0]!.path =
      'packages/runar-java/src/test/java/runar/lang/sdk/MinimalDataRoundTripTest.java';
    expect(checkNoRoundTripOnly(rows, ROUND_TRIP_ONLY_PATHS).join('\n')).toMatch(/own inverse/);
  });

  it('a denylist entry whose file was renamed away fails the liveness gate', () => {
    // Exactly the decay this gate exists for: the denylist keeps listing a
    // path nobody can cite any more, so it denies nothing and the RENAMED file
    // becomes citable with no gate firing.
    const stale = new Set([
      ...ROUND_TRIP_ONLY_PATHS,
      'packages/runar-sdk/src/__tests__/renamed-away.test.ts',
    ]);
    expect(checkDenylistLiveness(ROUND_TRIP_ONLY_PATHS)).toEqual([]);
    expect(checkDenylistLiveness(stale).join('\n')).toMatch(/silently stops denying anything/);
  });
});

describe('RED-PROOF: gate 8 — the required set cannot be shrunk red-to-green', () => {
  it('dropping a required construct below the committed floor fails', () => {
    const rows = clone(loadLedger());
    expect(
      checkRequiredSetIntegrity(REQUIRED_CONSTRUCTS, rows, MIN_REQUIRED_CONSTRUCTS),
    ).toEqual([]);
    const shrunk = REQUIRED_CONSTRUCTS.filter((id) => id !== 'state-bool');
    expect(
      checkRequiredSetIntegrity(shrunk, rows, MIN_REQUIRED_CONSTRUCTS).join('\n'),
    ).toMatch(/below the committed floor/);
  });

  it('a ledger row with no REQUIRED_CONSTRUCTS entry fails (the reverse direction)', () => {
    const rows = clone(loadLedger());
    rows.push({
      id: 'smuggled-in-construct',
      category: 'wire',
      description: 'a row added without declaring it required',
      severity: 'fund-critical',
      status: 'UNCOVERED',
      issue: 'none',
    });
    // Gate 3 (required -> row) stays green on this, which is the hole.
    const present = new Set(rows.map((r) => String(r.id)));
    expect(REQUIRED_CONSTRUCTS.filter((id) => !present.has(id))).toEqual([]);
    expect(
      checkRequiredSetIntegrity(REQUIRED_CONSTRUCTS, rows, MIN_REQUIRED_CONSTRUCTS).join('\n'),
    ).toMatch(/smuggled-in-construct/);
  });

  it('a duplicated id in REQUIRED_CONSTRUCTS fails', () => {
    const rows = clone(loadLedger());
    expect(
      checkRequiredSetIntegrity(
        [...REQUIRED_CONSTRUCTS, 'state-bool'],
        rows,
        MIN_REQUIRED_CONSTRUCTS,
      ).join('\n'),
    ).toMatch(/duplicate id/);
  });
});
