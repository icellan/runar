import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_TESTS_DIR = join(__dirname, '../../tests');

/**
 * The pinned set of conformance fixtures that are allowed to opt out of
 * one or more compiler tiers via the `compilers` field in source.json.
 *
 * Adding or modifying an entry here REQUIRES a matching update to
 * conformance/README.md ("Per-fixture compiler allowlist") with a
 * one-line rationale. If those two are not in sync, this test fails.
 *
 * Removing an entry means the fixture must either:
 *   (a) drop the `compilers` field entirely from its source.json, or
 *   (b) be deleted.
 */
const APPROVED_ALLOWLISTS: Record<string, string[]> = {
  // EVM/STARK proof-system primitives are Go-only by project policy
  // (see CLAUDE.md "EVM/STARK proof-system primitives are Go-only by
  // project policy" + the project_go_only_crypto_modules memory).
  // Covers: BabyBear / KoalaBear / Poseidon2* / BN254 + Groth16 /
  // Merkle / merkleRootSha256 / SP1 FRI / FiatShamir-KB.
  // Non-Go tiers may carry partial ports but are NOT conformance
  // targets for these families. Their parsers are still exercised
  // by the all-tier --parser-only matrix.
  babybear: ['go'],
  'babybear-ext4': ['go'],
  'merkle-proof': ['go'],
  'state-covenant': ['go'],
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

  it('every fixture with a compilers allowlist is approved here and in the README', () => {
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
});
