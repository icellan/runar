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

    // R3-GK010-GAPS + D9: ANY SigHashPreimage property (readonly or mutable,
    // scalar or FixedArray element) is refused at its declaration with its own
    // diagnostic, pinned here literally.
    const PROP_PREIMAGE = (name: string): string =>
      `property '${name}' cannot hold a SigHashPreimage: a preimage stored in a property was fixed before ` +
      'the spending transaction existed, so it can never pass checkPreimage() and every field an extractor ' +
      'reads from it is unverified';
    it('every property corpus refusal carries the pinned diagnostic', () => {
      const props = data.refuse.filter((c) => /^(readonly|mutable|py-readonly|py-mutable|rs-mutable)-.*property/.test(c.name));
      expect(props.length).toBeGreaterThanOrEqual(12);
      expect(props.filter((c) => c.name.includes('mutable')).length).toBeGreaterThanOrEqual(6);
      for (const c of props) expect(c.error, c.name).toBe(PROP_PREIMAGE(c.name.includes('fixedarray') ? 'ps' : 'pre'));
    });
    for (const propFixture of [
      'N530-ts-readonly-preimage-property.runar.ts',
      'N531-ts-mutable-preimage-property.runar.ts',
    ]) {
      const propHeader = readFileSync(join(__dirname, propFixture), 'utf8');
      it(`${propFixture} documents the pinned diagnostic`, () => {
        expect(propHeader.replace(/\n(\/\/|#) +/g, ' ')).toContain(PROP_PREIMAGE('pre'));
      });
      for (const tier of TIERS) {
        it(`${tier.id} refuses ${propFixture} with the pinned diagnostic`, () => {
          const { status, out, diag } = run(tier, writeFile(propFixture, propHeader));
          expect(status, `${tier.id} accepted ${propFixture} (emitted "${out}")`).not.toBe(0);
          expect(diag).toContain(PROP_PREIMAGE('pre'));
        });
      }
    }

    // D14: an extractor (or a private method's SigHashPreimage parameter)
    // must be handed a checked preimage, never a ByteString or a laundered
    // value; one shared diagnostic, pinned here literally.
    const UNCHECKED_ARG = (fn: string): string =>
      `${fn}() needs a checked SigHashPreimage: its argument must be a SigHashPreimage parameter ` +
      '(one a public method must assert with checkPreimage()) or the implicit txPreimage of a ' +
      'StatefulSmartContract; any other value is not bound to the spending transaction, so every ' +
      'field an extractor reads from it is unverified';
    it('every extractor corpus refusal carries the pinned diagnostic', () => {
      const ext = data.refuse.filter((c) => c.name.startsWith('extractor-'));
      expect(ext.length).toBeGreaterThanOrEqual(10);
      for (const c of ext) {
        const fn = /^(\w+)\(\) needs/.exec(c.error)?.[1] ?? '';
        expect(c.error, c.name).toBe(UNCHECKED_ARG(fn));
      }
    });
    for (const [extFixture, fn] of [
      ['N533-ts-extractor-bytestring-param.runar.ts', 'extractAmount'],
      ['N534-ts-extractor-bytestring-property.runar.ts', 'extractLocktime'],
      ['N535-ts-extractor-laundered-local.runar.ts', 'extractAmount'],
    ] as const) {
      const extHeader = readFileSync(join(__dirname, extFixture), 'utf8');
      it(`${extFixture} documents the pinned diagnostic`, () => {
        expect(extHeader.replace(/\n(\/\/|#) +/g, ' ')).toContain(UNCHECKED_ARG(fn));
      });
      for (const tier of TIERS) {
        it(`${tier.id} refuses ${extFixture} with the pinned diagnostic`, () => {
          const { status, out, diag } = run(tier, writeFile(extFixture, extHeader));
          expect(status, `${tier.id} accepted ${extFixture} (emitted "${out}")`).not.toBe(0);
          expect(diag).toContain(UNCHECKED_ARG(fn));
        });
      }
    }
  });

  describe('D10: a stateless Rust-DSL contract cannot declare tx_preimage', () => {
    const D10 =
      'a stateless contract cannot declare tx_preimage: nothing checks it against the spending transaction, ' +
      'so every field read from it is unverified; use #[runar::stateful_contract], or take the preimage as a ' +
      'method parameter and assert!(check_preimage(&preimage))';
    const data = corpus<{
      refuse: Array<{ name: string; file: string; src: string; error: string }>;
      accept: Array<{ name: string; file: string; src: string }>;
    }>('rust-tx-preimage-cases.json');
    it('the corpus pins the shared diagnostic', () => {
      expect(data.refuse.length).toBeGreaterThanOrEqual(5);
      for (const c of data.refuse) expect(c.error, c.name).toBe(D10);
    });
    for (const c of data.refuse) {
      for (const tier of TIERS) {
        it(`${tier.id} refuses ${c.name}`, () => {
          const { status, out, diag } = run(tier, writeFile(c.file, c.src));
          expect(status, `${tier.id} accepted ${c.name} (emitted "${out}")`).not.toBe(0);
          expect(diag).toContain(D10);
        });
      }
    }
    for (const c of data.accept) {
      it(`every tier compiles ${c.name} to the same bytes`, () => {
        const input = writeFile(c.file, c.src);
        const hexes = TIERS.map((t) => compileHex(t, input));
        expect(new Set(hexes).size, TIERS.map((t, i) => `${t.id}: ${hexes[i]!.length}`).join(', ')).toBe(1);
      });
    }
    const fixture = 'N532-rs-stateless-tx-preimage.runar.rs';
    const header = readFileSync(join(__dirname, fixture), 'utf8');
    it(`${fixture} documents the pinned diagnostic`, () => {
      expect(header.replace(/\n(\/\/|#) +/g, ' ')).toContain(D10);
    });
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${fixture} with the pinned diagnostic`, () => {
        const { status, out, diag } = run(tier, writeFile(fixture, header));
        expect(status, `${tier.id} accepted ${fixture} (emitted "${out}")`).not.toBe(0);
        expect(diag).toContain(D10);
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

  describe('#199: a stateful contract that can never release its satoshis warns', () => {
    interface RtCase { name: string; file: string; src: string; warning?: string; warning_absent?: string }
    const data = corpus<{ warn: RtCase[]; nowarn: RtCase[] }>('release-trap-cases.json');
    // Pinned literally (the corpus could drift with it).
    const WARN = (c: string): string =>
      `contract '${c}' has no terminal method and no public method that calls addOutput/addRawOutput; ` +
      `its satoshis can never leave instances of '${c}'`;
    it('the corpus carries the pinned text', () => {
      for (const c of data.warn) expect(c.warning, c.name).toBe(WARN(/class (\w+)/.exec(c.src)![1]!));
    });
    for (const c of data.warn) {
      it(`every tier warns on ${c.name}, still compiling it to the same bytes`, () => {
        const input = writeFile(c.file, c.src);
        const hexes = new Set<string>();
        for (const tier of TIERS) {
          const { status, out, diag } = run(tier, input);
          expect(status, `${tier.id} refused ${c.name}: ${diag.slice(0, 400)}`).toBe(0);
          expect(diag, tier.id).toContain(c.warning);
          hexes.add(out.split('\n').pop()!.trim());
        }
        expect([...hexes]).toHaveLength(1);
      });
    }
    for (const c of data.nowarn) {
      it(`no tier warns on ${c.name}`, () => {
        const input = writeFile(c.file, c.src);
        for (const tier of TIERS) {
          const { status, diag } = run(tier, input);
          expect(status, `${tier.id} refused ${c.name}: ${diag.slice(0, 400)}`).toBe(0);
          expect(diag, tier.id).not.toContain(c.warning_absent);
        }
      });
    }
  });

  describe('D18: a state write with no state continuation is refused', () => {
    interface DcCase { name: string; file: string; src: string; error?: string }
    const data = corpus<{ refuse: DcCase[]; accept: DcCase[] }>('dropped-continuation-cases.json');
    // Pinned literally (the corpus could drift with it).
    const D18 = (m: string): string =>
      `method '${m}' writes contract state but emits no state continuation: it calls addRawOutput() without ` +
      'addOutput(), and a method that declares its own outputs gets no auto-injected continuation, so the state ' +
      "write would be lost and the contract's satoshis would leave with the spend. Add this.addOutput(satoshis, " +
      '...) to carry the new state, or stop writing state in a method meant to end the contract';
    it('the corpus carries the pinned text', () => {
      for (const c of data.refuse) expect(c.error, c.name).toBe(D18(/^method '(\w+)'/.exec(c.error!)![1]!));
    });
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
    for (const [f, m] of [
      ['N536-ts-raw-output-drops-state-write.runar.ts', 'lock'],
      ['N537-ts-raw-output-helper-drops-state-write.runar.ts', 'pay'],
      ['N538-py-raw-output-drops-state-write.runar.py', 'sendToScript'],
    ] as const) {
      const src = readFileSync(join(__dirname, f), 'utf8');
      it(`${f} documents the pinned diagnostic`, () => {
        expect(src.replace(/\n(\/\/|#) +/g, ' ')).toContain(D18(m));
      });
      for (const tier of TIERS) {
        it(`${tier.id} refuses ${f} with the pinned diagnostic`, () => {
          const { status, out, diag } = run(tier, writeFile(f, src));
          expect(status, `${tier.id} accepted ${f} (emitted "${out}")`).not.toBe(0);
          expect(diag).toContain(D18(m));
        });
      }
    }
  });

  // Follow-on of D18's FixedArray fix: validate / typecheck / sighash-validate
  // see the UNEXPANDED contract, where a FixedArray element write is still an
  // index_access. Before every tier counted it as a state write, a @sighash
  // SINGLE method whose only write was an element took the mutate-only auto
  // continuation unrefused (the value-skim shape sighash-validate exists for).
  describe('SINGLE + FixedArray element write is a mutate-only continuation', () => {
    const src = (write: string): string => `import { StatefulSmartContract, assert, FixedArray } from 'runar-lang';

class Sg extends StatefulSmartContract {
  slots: FixedArray<bigint, 2> = [0n, 0n];

  constructor() {
    super();
  }

  /** @sighash SINGLE|FORKID */
  public bump(i: bigint) {
    assert(i >= 0n && i < 2n);
    ${write}
  }
}
`;
    for (const write of ['this.slots[0] = 5n;', 'this.slots[i]++;']) {
      for (const tier of TIERS) {
        it(`${tier.id} refuses \`${write}\` under SINGLE`, () => {
          const { status, out, diag } = run(tier, writeFile('Sg.runar.ts', src(write)));
          expect(status, `${tier.id} accepted (emitted "${out}")`).not.toBe(0);
          // Case-insensitive: the Zig tier words the sentence break differently
          // ("...; a mutate-only"), a pre-existing wording drift.
          expect(diag.toLowerCase()).toContain('mutate-only single continuation is unsound');
        });
      }
    }
  });
});
