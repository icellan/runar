import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';

/**
 * F-205 — `.runar.java` annotation names, seven-tier parity.
 *
 * `parser_java.py`'s `_skip_annotations` only ever consumed a single bare
 * identifier after `@`, so a qualified annotation
 * (`@runar.lang.annotations.Public`) fell straight through to the type
 * parser and failed with the unrelated "expected type, got '.'" — and no
 * annotation name was ever checked against the names Rúnar recognizes, so a
 * misspelled `@Publlic` parsed with zero errors and silently left the method
 * at its default PRIVATE visibility. Probing all seven `.runar.java`
 * frontends against the TS reference found:
 *
 *   - qualified names: TS, Go, Zig, Ruby and the Java tier (real javac
 *     annotation resolution) already read the rightmost segment; Python and
 *     Rust did not — both failed to parse `@runar.lang.annotations.Public`
 *     at all;
 *   - unknown-annotation validation: only TS refused an unrecognized
 *     annotation name ("unsupported annotation @<name>"). Every other tier
 *     — Go, Rust, Python, Zig, Ruby, and the Java tier — silently ignored
 *     it, downgrading `@Publlic` to a plain (private) method with no
 *     diagnostic.
 *
 * Fixed in all six non-TS tiers to match the TS reference exactly: a
 * qualified name resolves by its rightmost segment, and a simple name
 * outside {Readonly, Public, Stateful, Override, SuppressWarnings} is the
 * shared diagnostic "unsupported annotation @<name>".
 *
 * What this proves:
 *   - every available tier compiles a method annotated with the qualified
 *     `@runar.lang.annotations.Public` to the same bytes as the bare
 *     `@Public` form, in both fold modes;
 *   - every available tier refuses `@Publlic` with the exact shared
 *     diagnostic the TS reference uses, not merely "some diagnostic".
 * What it does NOT prove: annotations on constructors or parameters (the TS
 *   reference does not validate those either); any surface other than
 *   `.runar.java`; hex-`L` integer literal suffixes (F-026, already fixed
 *   and unrelated to this item).
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

const DISC = (annotation: string): string => `class Disc extends SmartContract {
    @Readonly Bigint t;
    Disc(Bigint t) { super(t); this.t = t; }
    ${annotation}
    void check(Bigint x) { assertThat(x == t); }
}
`;

// TS reference bytes for the bare `@Public` form, identical in both fold
// modes (the method body has nothing to fold).
const PINNED_HEX = '009c';

const MISSPELLED = DISC('@Publlic');
const QUALIFIED = DISC('@runar.lang.annotations.Public');

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n195-java-annotations-'));
});

let seq = 0;
function write(src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, 'Disc.runar.java');
  writeFileSync(p, src);
  return p;
}

/** Run a tier and return its stderr+stdout; fail the test if it compiled. */
function refusalText(tier: Tier, file: string): string {
  const r = spawnSync(tier.cmd!, [...tier.prefix, ...tier.argsFor(file)], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${tier.id} could not run: ${r.error.message}`);
  if (r.status === 0) {
    throw new Error(`${tier.id}: compiled (${r.stdout.trim().slice(-40)}), expected a refusal`);
  }
  return `${r.stderr ?? ''}\n${r.stdout ?? ''}`;
}

describe('F-205 .runar.java annotation names — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (process.env.CI === 'true') expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const tier of tiers) {
      it(`${tier.id} (${mode}) compiles the qualified @runar.lang.annotations.Public form to the bare-@Public bytes`, () => {
        expect(compileHex(tier, write(QUALIFIED))).toBe(PINNED_HEX);
      });
    }
  }

  for (const tier of TIERS) {
    it(`${tier.id} refuses @Publlic with the shared "unsupported annotation" diagnostic`, () => {
      const out = refusalText(tier, write(MISSPELLED));
      expect(out).toContain('unsupported annotation @Publlic');
    });
  }
});
