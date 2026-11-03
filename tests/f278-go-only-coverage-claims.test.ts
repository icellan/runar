/**
 * F-278 (GK-GAP-005): two documents state which Go-only proof-system families
 * the conformance corpus exercises:
 *
 *   conformance/README.md, "##### Go-only crypto family":
 *     "These fixtures exercise the <list> Stack-IR codegen ..."
 *   conformance/runner/__tests__/allowlist-audit.test.ts, APPROVED_ALLOWLISTS:
 *     "// Covers: <list>."
 *
 * Both lists used to name BN254 / Groth16 (as well as KoalaBear, Poseidon2,
 * the SP1 FRI verifier and FiatShamir-KB). No conformance/tests fixture
 * calls any of those primitives. A reviewer reading either list would believe
 * the corpus holds goldens for pairing / Groth16 codegen when it holds none.
 *
 * This test parses both lists and requires that every family they name is
 * called by the source of at least one conformance/tests fixture (resolved
 * through each fixture's source.json). It fails closed: a list that cannot be
 * found, or a name that matches no known family, is a failure, not a skip.
 *
 * What it proves: the two "covered by a conformance fixture" lists name only
 * families that some fixture's source actually calls.
 * What it does not prove: that the fixture exercises the family thoroughly,
 * that its golden is correct, or that families documented as NOT covered by a
 * fixture are covered anywhere else. BN254 is now called by the `bn254-pairing`
 * fixture (N-314); the Groth16 verifier shape still has no fixture.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TESTS_DIR = join(ROOT, 'conformance/tests');

// Family -> identifier pattern as it appears in contract source, in any of
// the nine surfaces (camelCase and snake_case spellings).
const FAMILIES: Record<string, RegExp> = {
  babybear: /\bbb_?(field|ext4)/i,
  koalabear: /\bkb_?(field|ext4)/i,
  poseidon2: /poseidon2/i,
  bn254: /\bbn254/i,
  groth16: /groth16/i,
  merkle: /merkle_?root/i,
  fri: /verify_?sp1_?fri/i,
  // FiatShamir-KB has no builtin of its own; it is emitted inside verifySP1FRI.
  fiatshamir: /verify_?sp1_?fri|fiat_?shamir/i,
};

function familyOf(token: string): string | undefined {
  const t = token
    .toLowerCase()
    .replace(/\*/g, '')
    .replace(/-witness$/, '')
    .replace(/^sp1\s+/, '')
    .replace(/[\s_-]/g, '');
  if (t === 'merklerootsha256') return 'merkle';
  if (t === 'fiatshamirkb') return 'fiatshamir';
  return t in FAMILIES ? t : undefined;
}

function splitList(list: string): string[] {
  return list
    .split(/[\/+]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function readmeClaim(): string[] {
  const text = readFileSync(join(ROOT, 'conformance/README.md'), 'utf8');
  const start = text.indexOf('##### Go-only crypto family');
  expect(start, 'README section "##### Go-only crypto family" not found').toBeGreaterThanOrEqual(0);
  const section = text.slice(start, text.indexOf('\n|', start));
  const m = /These fixtures exercise the (.+?) Stack-IR codegen/s.exec(section);
  expect(m, 'README sentence "These fixtures exercise the ... Stack-IR codegen" not found').not.toBeNull();
  return splitList(m![1]);
}

function allowlistClaim(): string[] {
  const text = readFileSync(join(ROOT, 'conformance/runner/__tests__/allowlist-audit.test.ts'), 'utf8');
  const m = /\/\/ Covers: ([^.]+)\./.exec(text);
  expect(m, '"// Covers: ...." comment not found in allowlist-audit.test.ts').not.toBeNull();
  return splitList(m![1].replace(/\n\s*\/\/\s*/g, ' '));
}

function fixtureSources(): Map<string, string> {
  const out = new Map<string, string>();
  for (const name of readdirSync(TESTS_DIR)) {
    const sj = join(TESTS_DIR, name, 'source.json');
    if (!existsSync(sj)) continue;
    const spec = JSON.parse(readFileSync(sj, 'utf8')) as { sources?: Record<string, string> };
    let text = '';
    for (const rel of Object.values(spec.sources ?? {})) {
      const p = resolve(TESTS_DIR, name, rel);
      if (existsSync(p)) text += readFileSync(p, 'utf8') + '\n';
    }
    out.set(name, text);
  }
  return out;
}

describe('F-278: Go-only families claimed as conformance-covered have a fixture', () => {
  const sources = fixtureSources();

  for (const [label, claim] of [
    ['conformance/README.md Go-only section', readmeClaim],
    ['allowlist-audit.test.ts "Covers:" comment', allowlistClaim],
  ] as const) {
    it(`${label}: every named family is called by some conformance fixture`, () => {
      const tokens = claim();
      expect(tokens.length).toBeGreaterThan(0);
      const problems: string[] = [];
      for (const tok of tokens) {
        const fam = familyOf(tok);
        if (!fam) {
          problems.push(`"${tok}": not a known Go-only family`);
          continue;
        }
        const hits = [...sources].filter(([, src]) => FAMILIES[fam]!.test(src)).map(([n]) => n);
        if (hits.length === 0) problems.push(`"${tok}": no conformance/tests fixture source calls it`);
      }
      expect(problems).toEqual([]);
    });
  }
});
