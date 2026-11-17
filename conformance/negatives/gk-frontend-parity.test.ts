import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BrokenTier, REPO, Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * Grok v1 frontend findings, all seven tiers through their one-shot
 * `source -> hex` CLIs.
 *
 * - GK-BUG-015: a repeated method name (two publics, two privates where one
 *   consumes a Sig, a public/private clash) is refused by every tier with the
 *   one shared diagnostic, within a hard timeout (the duplicate-private shape
 *   made several tiers' affine-consumption fixpoint spin); each renamed twin
 *   compiles to the same bytes in every tier. Corpus:
 *   duplicate-method-cases.json.
 * - GK-GAP-010: a public method whose SigHashPreimage parameter is not
 *   checked on every path is refused by every tier with the shared
 *   diagnostic; every accepted shape compiles to the same bytes in every tier.
 *   R2-GK010-ASSERT: only `checkPreimage(p)` as the asserted condition of
 *   assert(...) (or a conjunct of its top-level && chain) counts; discarded,
 *   bound, negated, ||-ed, compared, condition-position and helper-returned
 *   calls are refused. Corpus: preimage-checked-cases.json.
 * - GK-GAP-013: every tier still refuses each malformed intent-intrinsic shape
 *   at compile time (the lowerer backstop itself is pinned by each tier's unit
 *   tests, since no CLI reaches the lowerer without typecheck). Corpus:
 *   intent-shape-cases.json.
 * - GK-GAP-005/006: an upper-case `.RUNAR.{TS,PY,ZIG,RS}` file (including a
 *   TS contract carrying a `@sighash` comment directive) compiles to the same
 *   hex as its lower-case twin, a comment directive on an upper-case
 *   `.RUNAR.SOL` file is still refused, and a valid TypeScript contract saved
 *   as `.runar.xyz` is refused with the shared unsupported-extension
 *   diagnostic. Each file gets its own directory (macOS is case-insensitive).
 *
 * Does not prove: the library-API "no file name means TypeScript" rule (a CLI
 * always has a name; each tier's unit tests pin it), or that the accepted
 * preimage shapes are spendable on chain.
 */

const ROOT = mkdtempSync(join(tmpdir(), 'gk-frontend-'));
let seq = 0;
const writeFile = (fileName: string, content: string): string => {
  const d = join(ROOT, String(seq++));
  mkdirSync(d);
  const p = join(d, fileName);
  writeFileSync(p, content);
  return p;
};

const TIERS: Tier[] = buildSourceTiers().filter((t) => t.cmd !== null);

/** Hang guard for the duplicate-private shape: well under the harness default. */
const HANG_TIMEOUT_MS = 60_000;

function run(tier: Tier, input: string, timeoutMs = tier.timeoutMs): { status: number; out: string; diag: string } {
  if (tier.cmd === null) throw new BrokenTier(`${tier.id}: no toolchain`);
  const argv = [...tier.prefix, ...tier.argsFor(input)];
  const res = spawnSync(tier.cmd, argv, {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: Math.max(timeoutMs, tier.id === 'ts' ? tier.timeoutMs : 0),
    maxBuffer: 64 * 1024 * 1024,
  });
  const where = `${tier.id} (${tier.cmd} ${argv.join(' ')})`;
  if (res.error) throw new BrokenTier(`${where} could not run (timeout = hang?): ${res.error.message}`);
  if (res.signal !== null) throw new BrokenTier(`${where} killed by ${res.signal}`);
  if (res.status === null) throw new BrokenTier(`${where}: no exit status`);
  return { status: res.status, out: (res.stdout ?? '').trim(), diag: `${res.stderr ?? ''}\n${res.stdout ?? ''}` };
}

const corpus = <T>(name: string): T => JSON.parse(readFileSync(join(__dirname, name), 'utf8')) as T;

describe('Grok v1 frontend findings (all 7 tiers)', () => {
  it('every tier is built (strict in CI, ">=2" locally)', () => {
    if (isCiEnv(process.env)) {
      expect(TIERS.map((t) => t.id).sort()).toEqual(['go', 'java', 'python', 'ruby', 'rust', 'ts', 'zig']);
    }
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
  });

  describe('GK-BUG-015: duplicate method names', () => {
    const { cases } = corpus<{ cases: Array<{ name: string; file: string; src: string; twin: string; error: string }> }>(
      'duplicate-method-cases.json',
    );
    for (const c of cases) {
      for (const tier of TIERS) {
        it(`${tier.id} refuses ${c.name} with the shared diagnostic`, () => {
          const { status, out, diag } = run(tier, writeFile(c.file, c.src), HANG_TIMEOUT_MS);
          expect(status, `${tier.id} accepted ${c.name} (emitted "${out}")`).not.toBe(0);
          expect(diag).toContain(c.error);
        });
      }
      it(`every tier compiles the renamed twin of ${c.name} to the same bytes`, () => {
        const input = writeFile(c.file, c.twin);
        const hexes = new Set(TIERS.map((t) => compileHex(t, input)));
        expect([...hexes]).toHaveLength(1);
      });
    }
  });

  describe('GK-GAP-010: SigHashPreimage parameter checked on every path', () => {
    const data = corpus<{
      refuse: Array<{ name: string; file: string; src: string; error: string }>;
      accept: Array<{ name: string; file: string; src: string }>;
    }>('preimage-checked-cases.json');
    for (const c of data.refuse) {
      for (const tier of TIERS) {
        it(`${tier.id} refuses ${c.name} with the shared diagnostic`, () => {
          const { status, out, diag } = run(tier, writeFile(c.file, c.src));
          expect(status, `${tier.id} accepted ${c.name} (emitted "${out}")`).not.toBe(0);
          expect(diag).toContain(c.error);
        });
      }
    }
    for (const c of data.accept) {
      it(`every tier compiles ${c.name} to the same bytes`, () => {
        const input = writeFile(c.file, c.src);
        const hexes = new Set(TIERS.map((t) => compileHex(t, input)));
        expect([...hexes]).toHaveLength(1);
      });
    }

    // R3-GK010-WORDING: only an ASSERTED checkPreimage(p) counts
    // (R2-GK010-ASSERT), so the diagnostic says so. The text is pinned here
    // literally, not only read back from the corpus, and checked on the
    // checked-in rejection fixtures too (rejection-parity.test.ts grades
    // their verdict only, never the text).
    const GK010_SPEND_TXPREIMAGE = "public method 'spend' must assert checkPreimage(txPreimage) on every path";
    it('every GK-010 corpus refusal carries the pinned diagnostic', () => {
      const gk010 = data.refuse.filter((c) => c.error.startsWith('public method '));
      expect(gk010.length).toBeGreaterThan(20);
      for (const c of gk010) expect(c.error, c.name).toBe(GK010_SPEND_TXPREIMAGE);
    });
    const fixtures = [
      'N511-ts-unchecked-preimage.runar.ts',
      'N520-ts-preimage-check-discarded.runar.ts',
      'N521-ts-preimage-check-bound-to-local.runar.ts',
      'N522-ts-preimage-check-negated.runar.ts',
      'N523-ts-preimage-check-or-ed.runar.ts',
      'N524-ts-preimage-check-if-condition.runar.ts',
      'N525-ts-preimage-check-ternary-condition.runar.ts',
      'N526-ts-preimage-check-eq-true.runar.ts',
      'N527-ts-preimage-check-double-negated.runar.ts',
      'N528-ts-preimage-check-helper-returns.runar.ts',
      'N529-py-preimage-check-discarded.runar.py',
    ];
    for (const f of fixtures) {
      const header = readFileSync(join(__dirname, f), 'utf8');
      it(`${f} documents the pinned diagnostic`, () => {
        expect(header.replace(/\n(\/\/|#) +/g, ' ')).toContain(GK010_SPEND_TXPREIMAGE);
      });
      for (const tier of TIERS) {
        it(`${tier.id} refuses ${f} with the pinned diagnostic`, () => {
          const { status, out, diag } = run(tier, writeFile(f, header));
          expect(status, `${tier.id} accepted ${f} (emitted "${out}")`).not.toBe(0);
          expect(diag).toContain(GK010_SPEND_TXPREIMAGE);
        });
      }
    }

    // R3-GK010-GAPS: a readonly SigHashPreimage property is refused at its
    // declaration with its own diagnostic, pinned here literally.
    const RO_PREIMAGE_PRE =
      "readonly property 'pre' cannot hold a SigHashPreimage: a preimage fixed in the locking script " +
      'can never pass checkPreimage(), so every field an extractor reads from it is unverified';
    it('every readonly-property corpus refusal carries the pinned diagnostic', () => {
      const ro = data.refuse.filter((c) => c.error.startsWith('readonly property '));
      expect(ro.length).toBeGreaterThanOrEqual(6);
      for (const c of ro.filter((x) => x.name !== 'readonly-fixedarray-property')) expect(c.error, c.name).toBe(RO_PREIMAGE_PRE);
    });
    const roFixture = 'N530-ts-readonly-preimage-property.runar.ts';
    const roHeader = readFileSync(join(__dirname, roFixture), 'utf8');
    it(`${roFixture} documents the pinned diagnostic`, () => {
      expect(roHeader.replace(/\n(\/\/|#) +/g, ' ')).toContain(RO_PREIMAGE_PRE);
    });
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${roFixture} with the pinned diagnostic`, () => {
        const { status, out, diag } = run(tier, writeFile(roFixture, roHeader));
        expect(status, `${tier.id} accepted ${roFixture} (emitted "${out}")`).not.toBe(0);
        expect(diag).toContain(RO_PREIMAGE_PRE);
      });
    }
  });

  describe('GK-GAP-013: malformed intent intrinsics are still refused', () => {
    const { cases } = corpus<{ cases: Array<{ name: string; src: string }> }>('intent-shape-cases.json');
    for (const c of cases) {
      for (const tier of TIERS) {
        it(`${tier.id} refuses ${c.name}`, () => {
          const { status, out } = run(tier, writeFile('Bad.runar.ts', c.src));
          expect(status, `${tier.id} accepted ${c.name} (emitted "${out}")`).not.toBe(0);
        });
      }
    }
  });

  describe('GK-GAP-005/006: file-extension dispatch', () => {
    const ts = readFileSync(join(REPO, 'examples/ts/p2pkh/P2PKH.runar.ts'), 'utf8');
    const py = readFileSync(join(REPO, 'examples/python/p2pkh/P2PKH.runar.py'), 'utf8');
    const read = (p: string): string => readFileSync(join(REPO, p), 'utf8');
    const pairs: Array<[string, string, string]> = [
      [ts, 'P2PKH.runar.ts', 'P2PKH.RUNAR.TS'],
      [py, 'P2PKH.runar.py', 'P2PKH.RUNAR.PY'],
      // .runar.zig selects the Zig surface's relaxed validator (no super())
      // and, like .runar.rs, the immutable-local check: the upper-case name
      // must reach the same surface-specific passes.
      [read('examples/zig/p2pkh/P2PKH.runar.zig'), 'P2PKH.runar.zig', 'P2PKH.RUNAR.ZIG'],
      [read('examples/rust/p2pkh/P2PKH.runar.rs'), 'P2PKH.runar.rs', 'P2PKH.RUNAR.RS'],
      // The TS surface honours the @sighash comment directive: the upper-case
      // name must not lose it.
      [read('conformance/ir-roundtrip/SighashSingle.runar.ts'), 'SighashSingle.runar.ts', 'SighashSingle.RUNAR.TS'],
    ];
    const sol = `// @sighash SINGLE|FORKID\n${read('examples/sol/p2pkh/P2PKH.runar.sol')}`;
    for (const tier of TIERS) {
      for (const [src, lower, upper] of pairs) {
        it(`${tier.id}: ${upper} compiles to the same hex as ${lower}`, () => {
          const want = compileHex(tier, writeFile(lower, src));
          expect(compileHex(tier, writeFile(upper, src))).toBe(want);
        });
      }
      it(`${tier.id}: a comment @sighash directive on an upper-case .RUNAR.SOL is still refused`, () => {
        const { status, out, diag } = run(tier, writeFile('P2PKH.RUNAR.SOL', sol));
        expect(status, `${tier.id} accepted the directive (emitted "${out}")`).not.toBe(0);
        expect(diag).toContain('@sighash directive (issue #123) is not supported as a comment by the Solidity surface parser');
      });
      it(`${tier.id}: a valid TypeScript contract named .runar.xyz is refused`, () => {
        const { status, out, diag } = run(tier, writeFile('P2PKH.runar.xyz', ts));
        expect(status, `${tier.id} accepted .runar.xyz (emitted "${out}")`).not.toBe(0);
        expect(diag).toContain('unsupported file extension: ');
        expect(diag).toContain(
          'P2PKH.runar.xyz (expected .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs, ' +
            '.runar.py, .runar.rb, .runar.zig, or .runar.java)',
        );
      });
    }
  });
});
