import { describe, it, expect, afterAll } from 'vitest';
import { readFileSync, readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { readFixtureCompilerAllowlist, readFixtureFoldOnMatchesGolden } from '../runner.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_TESTS_DIR = join(__dirname, '../../tests');

/**
 * The pinned set of conformance fixtures that are allowed to opt out of
 * one or more compiler tiers via the `compilers` field in source.json.
 *
 * This constant is the SOURCE OF TRUTH the test enforces: it asserts that
 * every fixture's source.json `compilers` field matches an entry here, and
 * that every entry here corresponds to a real fixture. It does NOT read
 * conformance/README.md. When adding/modifying an entry, also update
 * conformance/README.md ("Per-fixture compiler allowlist") with a one-line
 * rationale — that documentation sync is a convention, not enforced here.
 *
 * Removing an entry means the fixture must either:
 *   (a) drop the `compilers` field entirely from its source.json, or
 *   (b) be deleted.
 */
const APPROVED_ALLOWLISTS: Record<string, string[]> = {
  // EVM/STARK proof-system primitives are Go-only by project policy
  // (see CLAUDE.md "EVM/STARK proof-system primitives are Go-only by
  // project policy" + the project_go_only_crypto_modules memory).
  // Covers: BabyBear / merkleRootSha256 / BN254.
  // BN254 is the four-pair pairing check `bn254MultiPairing4` in
  // `bn254-pairing` (N-314), whose golden is executed by the precompiled-hex
  // spec witnesses/real-crypto/bn254-pairing.json.
  // The policy also scopes KoalaBear, Poseidon2*, the Groth16 verifier
  // shape, SP1 FRI and FiatShamir-KB to Go. No conformance fixture calls any
  // of them: they are covered only by Go unit and integration tests.
  // tests/f278-go-only-coverage-claims.test.ts fails if the "Covers:" list
  // names a family that no fixture calls.
  // Non-Go tiers may carry partial ports but are NOT conformance
  // targets for these families. Their parsers are still exercised
  // by the all-tier --parser-only matrix.
  babybear: ['go'],
  'babybear-ext4': ['go'],
  'merkle-proof': ['go'],
  'state-covenant': ['go'],
  'bn254-pairing': ['go'],
};

function listFixtureDirs(): string[] {
  return readdirSync(CONFORMANCE_TESTS_DIR).filter((name) => {
    const full = join(CONFORMANCE_TESTS_DIR, name);
    try {
      return statSync(full).isDirectory();
    } catch {
      return false;
    }
  });
}

function readSourceJson(fixture: string): Record<string, unknown> | null {
  const p = join(CONFORMANCE_TESTS_DIR, fixture, 'source.json');
  try {
    const raw = readFileSync(p, 'utf-8');
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function actualAllowlists(): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const fixture of listFixtureDirs()) {
    const sj = readSourceJson(fixture);
    if (!sj) continue;
    const compilers = sj.compilers;
    if (!Array.isArray(compilers) || compilers.length === 0) continue;
    out[fixture] = compilers.map(String);
  }
  return out;
}

function sameSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sa = [...a].sort();
  const sb = [...b].sort();
  return sa.every((v, i) => v === sb[i]);
}

const REMEDIATION = [
  'To fix:',
  '  1. Add the fixture to APPROVED_ALLOWLISTS in conformance/runner/__tests__/allowlist-audit.test.ts',
  '     with the exact compiler list from its source.json.',
  '  2. Document the rationale in conformance/README.md under',
  '     "Per-fixture compiler allowlist" so reviewers can see why the fixture',
  '     opts out of tiers it does not run on.',
  '  3. If the allowlist is no longer needed (the missing primitive landed in',
  '     every tier), remove the `compilers` field from source.json AND drop',
  '     the entry from APPROVED_ALLOWLISTS + the README table.',
].join('\n');

describe('conformance allowlist audit', () => {
  const actual = actualAllowlists();
  const approved = APPROVED_ALLOWLISTS;

  it('every fixture with a compilers allowlist is approved in APPROVED_ALLOWLISTS', () => {
    const unapproved = Object.keys(actual)
      .filter((k) => !(k in approved))
      .sort();
    expect(
      unapproved,
      `Found unapproved compiler allowlist(s) in source.json: ${unapproved.join(', ')}\n${REMEDIATION}`,
    ).toEqual([]);
  });

  it('no APPROVED_ALLOWLISTS entry is stale (every approved fixture still has the field)', () => {
    const stale = Object.keys(approved)
      .filter((k) => !(k in actual))
      .sort();
    expect(
      stale,
      `APPROVED_ALLOWLISTS entries with no matching source.json allowlist: ${stale.join(', ')}\n${REMEDIATION}`,
    ).toEqual([]);
  });

  it('approved compiler list matches the actual source.json allowlist (exact set match)', () => {
    const mismatches: string[] = [];
    for (const [fixture, expected] of Object.entries(approved)) {
      const got = actual[fixture];
      if (!got) continue;
      if (!sameSet(got, expected)) {
        mismatches.push(
          `  - ${fixture}: source.json=${JSON.stringify(got)} approved=${JSON.stringify(expected)}`,
        );
      }
    }
    expect(
      mismatches,
      `Allowlist drift detected:\n${mismatches.join('\n')}\n${REMEDIATION}`,
    ).toEqual([]);
  });

  // Every fixture with a `compilers` allowlist MUST also carry a non-empty
  // `compilersJustification` string. The compilers allowlist is reserved
  // for genuinely scoped tiers (Go-only crypto, Java-deferred Stack-IR);
  // requiring an in-file rationale forces the author to articulate WHY a
  // tier is excluded so a future reader (or auditor) can tell at a glance
  // whether the opt-out is still valid. Mirrors the parser-coverage
  // discipline applied to `parserSkip`/`parserSkipReason` in the runner.
  it('every fixture with a compilers allowlist carries a non-empty compilersJustification', () => {
    const missing: string[] = [];
    for (const fixture of Object.keys(actual)) {
      const sj = readSourceJson(fixture);
      const j = sj?.compilersJustification;
      if (typeof j !== 'string' || j.trim() === '') {
        missing.push(`  - ${fixture}: source.json carries "compilers" but no non-empty "compilersJustification"`);
      }
    }
    expect(
      missing,
      `compilersJustification missing or empty:\n${missing.join('\n')}\n` +
      `Add a "compilersJustification" string to source.json explaining ` +
      `why the listed tiers are scoped (e.g. "Codegen for {primitive} is ` +
      `Go-only by project policy — see CLAUDE.md" or "Java Stack-IR pass ` +
      `for {feature} is deferred — see HANDOFF").`,
    ).toEqual([]);
  });

  // `parserSkip` in source.json is an escape hatch from the "no exceptions"
  // frontend-parity invariant (every available tier must parse every format
  // for every fixture). It has ZERO users today. This pin governs it the same
  // way APPROVED_ALLOWLISTS governs the codegen allowlist: it MUST stay empty
  // unless a fixture is explicitly approved here — so a parser opt-out cannot
  // land silently and erode frontend parity. (The runner also requires a
  // non-empty parserSkipReason at runtime, but a self-written reason string is
  // not review-gated; this audit pin is.)
  //
  // R-094 added the first two users. Both skip `.runar.java` for the same
  // reason, and it is a decision rather than a deferral: `FixedArray<T, N>`
  // has no spelling the Java surface can express — an integer literal in a
  // Java type-argument list is a javac PARSE error, so nothing survives
  // javax.tools.JavaCompiler — and `runar.lang.types.FixedArray` was withdrawn
  // under N-122 rather than left as a trap. The Java COMPILER is still a full
  // parity target for these fixtures' other eight surfaces.
  //
  // N-093 added the third, `embed-always-fixed-array`, for the same reason
  // (user decision R38: the one approved `.runar.java` skip, like the other
  // FixedArray fixtures).
  //
  // F-352 added the fourth, `state-array-set`, for the same reason: it is the
  // second witness for the mutable-state shape FixedArray<bigint, 4>, and no
  // Java spelling of a FixedArray property exists.
  //
  // GK-GAP-003 added `ternary-expression`, which pins the conditional
  // EXPRESSION `c ? a : b`. User decision: only the surfaces that have ternary
  // syntax carry it (.ts/.sol/.rb/.java `c ? a : b`, .py `a if c else b`; the
  // N491 paren-ternary negatives confirm all five parse it on every tier). The
  // Move, Go, Rust-DSL and Zig surfaces have no conditional expression -- `if`
  // is a statement there -- so there is nothing for them to spell. All seven
  // compilers stay full hex/ANF parity targets for the five surfaces.
  //
  // `current-block-height-helper-ternary` follows it for the same reason: it
  // pins currentBlockHeight() in a ternary arm (and in a private helper), so
  // it ships only the five surfaces with a conditional expression.
  const APPROVED_PARSER_SKIPS: Record<string, string[]> = {
    'current-block-height-helper-ternary': ['.runar.go', '.runar.move', '.runar.rs', '.runar.zig'],
    'embed-always-fixed-array': ['.runar.java'],
    'fixed-array-index': ['.runar.java'],
    'fixed-array-write': ['.runar.java'],
    'state-array-set': ['.runar.java'],
    'ternary-expression': ['.runar.go', '.runar.move', '.runar.rs', '.runar.zig'],
  };
  it('no fixture opts a format out of parser coverage unless approved (parserSkip stays governed)', () => {
    const offenders: string[] = [];
    for (const fixture of listFixtureDirs()) {
      const sj = readSourceJson(fixture);
      const ps = sj?.parserSkip;
      if (!Array.isArray(ps) || ps.length === 0) continue;
      const approved = APPROVED_PARSER_SKIPS[fixture];
      if (approved === undefined) {
        offenders.push(`  - ${fixture}: parserSkip=${JSON.stringify(ps)} not in APPROVED_PARSER_SKIPS`);
        continue;
      }
      // Approval is per-FORMAT, not per-fixture. Key membership alone would let
      // an approved fixture widen its skip list later — approve `.runar.java`
      // once and `.runar.py` rides in free — which is the shape of erosion this
      // pin exists to stop.
      const extra = [...ps].sort().filter((ext) => !approved.includes(ext));
      const stale = [...approved].sort().filter((ext) => !ps.includes(ext));
      if (extra.length > 0) {
        offenders.push(
          `  - ${fixture}: parserSkip contains ${JSON.stringify(extra)}, approved for ` +
            `${JSON.stringify(approved)} only`,
        );
      }
      if (stale.length > 0) {
        offenders.push(
          `  - ${fixture}: APPROVED_PARSER_SKIPS lists ${JSON.stringify(stale)} which the ` +
            `fixture no longer skips — drop the stale approval`,
        );
      }
    }
    expect(
      offenders,
      `Unapproved parserSkip(s) — frontend parity is "no exceptions". Add the fixture ` +
      `to APPROVED_PARSER_SKIPS with a rationale (and document it) or remove the ` +
      `parserSkip:\n${offenders.join('\n')}`,
    ).toEqual([]);
  });

  // Four independent resolvers read source.json (runner.ts, witnesses/
  // differential.test.ts, witnesses/real-crypto-execution.test.ts,
  // script_execution_test.go) and they disagree on precedence when a fixture
  // declares BOTH the legacy `path` and the multi-format `sources` map: the
  // runner prefers `path`, the other three prefer `sources`. Rather than
  // duplicate a precedence rule across three languages, forbid the overlap —
  // then all four are provably equivalent. (The runner throws on this too; this
  // pin catches it without needing a full conformance run.)
  it('no fixture declares both "path" and "sources" in source.json', () => {
    const both = listFixtureDirs()
      .filter((f) => {
        const sj = readSourceJson(f);
        return !!sj && 'path' in sj && 'sources' in sj;
      })
      .sort();
    expect(
      both,
      `source.json must declare sources EXACTLY one way; these declare both ` +
      `"path" and "sources", so different harnesses could compile different ` +
      `files for the same fixture: ${both.join(', ')}`,
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// GK-GAP-002 (user decision: option (a)). A `"compilers"`-allowlisted fixture
// has only one tier, so under fold-ON its rows compare nothing unless the
// fixture opts into `foldOnMatchesGolden` (N-473) — R132 keeps such rows
// labelled VACUOUS rather than failed, and R190 made the flag opt-in. That
// let a NEW Go-only fixture land vacuous-but-green under fold-ON. This rule
// closes it statically: every allowlisted fixture must set
// `"foldOnMatchesGolden": true`, or carry a whole-fixture entry with a
// non-empty `reason` in conformance/fold-on-allowlist.json (which states why
// it cannot be compared). R132's label semantics are unchanged.
// ---------------------------------------------------------------------------

const FOLD_ON_ALLOWLIST = join(__dirname, '../../fold-on-allowlist.json');

/**
 * Allowlisted fixtures under `testsDir` that would run vacuous under fold-ON.
 * Reads source.json through the runner's own loaders, so a malformed
 * `compilers` list or a non-`true` `foldOnMatchesGolden` throws here exactly
 * as it does in the runner; a fold-on-allowlist entry without a non-empty
 * `reason` is refused the same way `loadFoldOnAllowlist` refuses it.
 */
function foldOnCoverageGaps(testsDir: string, foldOnAllowlistPath: string): string[] {
  const raw = JSON.parse(readFileSync(foldOnAllowlistPath, 'utf-8')) as { skip?: unknown };
  const wholeFixture = new Set<string>();
  for (const ent of Array.isArray(raw.skip) ? raw.skip : []) {
    const e = ent as Record<string, unknown>;
    if (typeof e?.fixture !== 'string' || typeof e.reason !== 'string' || e.reason.trim() === '') {
      throw new Error(
        `fold-on-allowlist.json entry rejected: every entry needs a fixture and a non-empty reason (${JSON.stringify(ent)})`,
      );
    }
    if (e.formats === undefined) wholeFixture.add(e.fixture);
  }
  const gaps: string[] = [];
  for (const fixture of readdirSync(testsDir).sort()) {
    const dir = join(testsDir, fixture);
    if (!statSync(dir).isDirectory()) continue;
    if (readFixtureCompilerAllowlist(dir) === null) continue;
    if (readFixtureFoldOnMatchesGolden(dir)) continue;
    if (wholeFixture.has(fixture)) continue;
    gaps.push(
      `${fixture}: "compilers" allowlist without "foldOnMatchesGolden": true or a ` +
        'whole-fixture fold-on-allowlist.json entry with a reason',
    );
  }
  return gaps;
}

describe('GK-GAP-002: compilers-allowlisted fixtures are not vacuous under fold-ON', () => {
  const tmp: string[] = [];
  afterAll(() => {
    for (const d of tmp) rmSync(d, { recursive: true, force: true });
  });

  /** A temp tests dir holding one copy of merkle-proof/source.json, edited by `edit`. */
  function tempCorpus(edit: (sj: Record<string, unknown>) => void, skip: unknown[] = []): {
    testsDir: string;
    allowlist: string;
  } {
    const root = mkdtempSync(join(tmpdir(), 'gk-gap-002-'));
    tmp.push(root);
    const testsDir = join(root, 'tests');
    mkdirSync(join(testsDir, 'merkle-proof'), { recursive: true });
    const sj = readSourceJson('merkle-proof')!;
    edit(sj);
    writeFileSync(join(testsDir, 'merkle-proof', 'source.json'), JSON.stringify(sj, null, 2));
    const allowlist = join(root, 'fold-on-allowlist.json');
    writeFileSync(allowlist, JSON.stringify({ skip }));
    return { testsDir, allowlist };
  }

  it('the real corpus has no gap', () => {
    expect(foldOnCoverageGaps(CONFORMANCE_TESTS_DIR, FOLD_ON_ALLOWLIST)).toEqual([]);
  });

  it('an allowlisted fixture without foldOnMatchesGolden or a fold-on entry is a gap', () => {
    const { testsDir, allowlist } = tempCorpus((sj) => {
      delete sj.foldOnMatchesGolden;
    });
    expect(foldOnCoverageGaps(testsDir, allowlist)).toEqual([
      'merkle-proof: "compilers" allowlist without "foldOnMatchesGolden": true or a ' +
        'whole-fixture fold-on-allowlist.json entry with a reason',
    ]);
  });

  it('a whole-fixture fold-on-allowlist entry with a reason closes the gap', () => {
    const { testsDir, allowlist } = tempCorpus(
      (sj) => {
        delete sj.foldOnMatchesGolden;
      },
      [{ fixture: 'merkle-proof', reason: 'folding moves the bytes; see tracking' }],
    );
    expect(foldOnCoverageGaps(testsDir, allowlist)).toEqual([]);
  });

  it('a format-scoped entry does not close the gap (the other formats stay vacuous)', () => {
    const { testsDir, allowlist } = tempCorpus(
      (sj) => {
        delete sj.foldOnMatchesGolden;
      },
      [{ fixture: 'merkle-proof', formats: ['.runar.ts'], reason: 'one format only' }],
    );
    expect(foldOnCoverageGaps(testsDir, allowlist)).toHaveLength(1);
  });

  it('an entry with an empty reason is refused, as the runner refuses it', () => {
    const { testsDir, allowlist } = tempCorpus(
      (sj) => {
        delete sj.foldOnMatchesGolden;
      },
      [{ fixture: 'merkle-proof', reason: '  ' }],
    );
    expect(() => foldOnCoverageGaps(testsDir, allowlist)).toThrow(/reason/);
  });

  it('foldOnMatchesGolden other than true is refused, as the runner refuses it', () => {
    const { testsDir, allowlist } = tempCorpus((sj) => {
      sj.foldOnMatchesGolden = 'yes';
    });
    expect(() => foldOnCoverageGaps(testsDir, allowlist)).toThrow(/foldOnMatchesGolden/);
  });
});
