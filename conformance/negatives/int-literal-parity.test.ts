import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ALL_TIER_IDS, REPO, Tier, buildSourceTiers } from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * F-026 (user decision R15) — seven-tier POSITIVE parity for integer literals.
 *
 * rejection-parity.test.ts proves every tier refuses the malformed literals
 * and absorbing shapes (N68-N80). This file pins the accepted side: on every
 * surface, every literal form the host language defines
 * (`int-literal-cases.json`, generated from the host toolchains) compiles to
 * the same bytes as its decimal spelling, in all seven tiers.
 *
 * It also keeps attempt 1's execution proof. The zig shape
 * `runar.assert(amount > 0b1010)`, with a ByteString parameter named `b1010`
 * in scope, compiled in the pre-fix reference tier to `7c00a077`
 * (`amount > 0`), and @bsv/sdk Spend.validate accepted amount = 5 against it.
 * Every tier must now emit the reference bytes for `amount > 10`, which reject
 * amount = 5 and accept amount = 11.
 *
 * Why a test here rather than a conformance fixture: a new fixture must be
 * stamped into conformance/script-size-baseline.json. The golden-provenance
 * gate guards that file, and only a route-B allowlist entry signed by a human
 * reviewer can justify a change to it.
 *
 * What this proves: for each surface, every available tier compiles a
 * contract that uses every accepted non-decimal / separated / suffixed form of
 * that surface to exactly the bytes of the same contract spelled in decimal,
 * and the tiers agree byte for byte. Java's two's-complement readings
 * (`0xFFFFFFFF` = -1, …) cannot be spelled as one decimal literal outside the
 * javac path, so for them only seven-tier agreement is asserted. The
 * exploit-shape artifact, compiled by every tier, is the reference script and
 * behaves as `> 10` under the real interpreter.
 * What it does NOT prove: fold-OFF output (the CLIs run in their fold-ON
 * default); anything about refused forms (rejection-parity.test.ts and each
 * tier's own F-026 suite cover those); or the Rust tier's value for a plain
 * `.runar.ts` number above 2^53, which it reads through f64 (N-028, a separate
 * item; those rows are checked in the other six tiers only).
 */

type Surface = 'ts' | 'sol' | 'move' | 'go' | 'rs' | 'py' | 'zig' | 'rb' | 'java';
const SURFACES: Surface[] = ['ts', 'sol', 'move', 'go', 'rs', 'py', 'zig', 'rb', 'java'];
const CASES = JSON.parse(readFileSync(join(__dirname, 'int-literal-cases.json'), 'utf8')).cases as Record<Surface, [string, string | null][]>;

/** A contract asserting `a > lit` for every literal in `lits`. */
function contract(surface: Surface, lits: string[]): string {
  const each = (f: (l: string) => string, sep = '\n') => lits.map(f).join(sep);
  switch (surface) {
    case 'ts':
      return `import { SmartContract, assert } from 'runar-lang';\n\nclass T extends SmartContract {\n  readonly target: bigint;\n\n  constructor(target: bigint) {\n    super(target);\n    this.target = target;\n  }\n\n  public verify(a: bigint): void {\n${each((l) => `    assert(a > ${l});`)}\n  }\n}\n`;
    case 'sol':
      return `pragma runar ^0.1.0;\n\ncontract T is SmartContract {\n    int immutable target;\n\n    constructor(int _target) {\n        target = _target;\n    }\n\n    function verify(int a) public {\n${each((l) => `        require(a > ${l});`)}\n    }\n}\n`;
    case 'move':
      return `module T {\n    use runar::types::{Int};\n\n    struct T {\n        target: Int,\n    }\n\n    public fun verify(contract: &T, a: Int) {\n${each((l) => `        assert!(a > ${l});`)}\n    }\n}\n`;
    case 'go':
      return `package contract\n\nimport runar "github.com/icellan/runar/packages/runar-go"\n\ntype T struct {\n\trunar.SmartContract\n\tTarget runar.Int \`runar:"readonly"\`\n}\n\nfunc (c *T) Verify(a runar.Int) {\n${each((l) => `\trunar.Assert(a > ${l})`)}\n}\n`;
    case 'rs':
      return `use runar::prelude::*;\n\n#[runar::contract]\nstruct T {\n    #[readonly]\n    target: Int,\n}\n\nimpl T {\n    pub fn verify(&self, a: Int) {\n${each((l) => `        assert!(a > ${l});`)}\n    }\n}\n`;
    case 'py':
      return `from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, a: Bigint):\n${each((l) => `        assert_(a > ${l})`)}\n`;
    case 'zig':
      return `const runar = @import("runar");\n\npub const T = struct {\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {\n        return .{ .target = target };\n    }\n\n    pub fn verify(self: *const T, a: i64) void {\n        _ = self;\n${each((l) => `        runar.assert(a > ${l});`)}\n    }\n};\n`;
    case 'rb':
      return `require 'runar'\n\nclass T < Runar::SmartContract\n  prop :target, Bigint\n\n  def initialize(target)\n    super(target)\n    @target = target\n  end\n\n  runar_public a: Bigint\n  def verify(a)\n${each((l) => `    assert a > ${l}`)}\n  end\nend\n`;
    case 'java':
      return `package t;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass T extends SmartContract {\n\n    @Readonly Bigint target;\n\n    T(Bigint target) {\n        super(target);\n        this.target = target;\n    }\n\n    @Public\n    void verify(Bigint a) {\n${each((l) => `        assertThat(a.gt(Bigint.of(${l})));`)}\n    }\n}\n`;
  }
}

/** The decimal spelling of a non-negative value on `surface`. */
function decimal(surface: Surface, value: string): string {
  return surface === 'java' && BigInt(value) > 2147483647n ? `${value}L` : value;
}

/** The accepted rows of a surface that are not already written in decimal. */
function forms(surface: Surface): { lit: string; value: string }[] {
  return CASES[surface]
    .filter((r): r is [string, string] => r[1] !== null && r[0] !== r[1])
    .map(([lit, value]) => ({ lit, value }));
}

const TIERS: Tier[] = buildSourceTiers();
const available = TIERS.filter((t) => t.cmd !== null);
const WORK = mkdtempSync(join(tmpdir(), 'f026-parity-'));

/** Compile `source` with `tier` and return the hex, or throw with its stderr. */
function hexOf(tier: Tier, source: string, file: string): string {
  const path = join(WORK, `${tier.id}-${file}`);
  writeFileSync(path, source);
  const r = spawnSync(tier.cmd!, [...tier.prefix, ...tier.argsFor(path)], {
    cwd: tier.cwd, encoding: 'utf-8', timeout: tier.timeoutMs,
  });
  if (r.status !== 0) {
    throw new Error(`${tier.id} refused ${file}: ${(r.stderr + r.stdout).replace(/\s+/g, ' ').slice(0, 400)}`);
  }
  return r.stdout.trim().split('\n').pop()!.trim();
}

describe('F-026 accepted integer literals: seven-tier value parity', () => {
  beforeAll(() => {
    if (isCiEnv(process.env)) expect(available.map((t) => t.id).sort()).toEqual([...ALL_TIER_IDS]);
  });

  it('the matrix names all seven tiers and at least the reference is available', () => {
    expect([...TIERS.map((t) => t.id)].sort()).toEqual([...ALL_TIER_IDS]);
    expect(available.some((t) => t.id === 'ts')).toBe(true);
  });

  for (const surface of SURFACES) {
    it(`.runar.${surface}: every accepted form compiles to its decimal spelling's bytes`, () => {
      const all = forms(surface);
      // N-028 (a separate item, not fixed here): the Rust tier reads a plain
      // `.runar.ts` number (no `n`) through f64, so above 2^53 it rounds.
      // Those rows are checked in every OTHER tier below.
      const n028 = (f: { lit: string; value: string }) =>
        surface === 'ts' && !f.lit.endsWith('n') && BigInt(f.value) >= 2n ** 53n;
      const positive = all.filter((f) => !f.value.startsWith('-') && !n028(f));
      const negative = all.filter((f) => f.value.startsWith('-'));
      expect(positive.length).toBeGreaterThanOrEqual(3);
      const file = `T.runar.${surface}`;
      const check = (lits: { lit: string; value: string }[], tiers: Tier[]) => {
        const test = contract(surface, lits.map((f) => f.lit));
        const control = contract(surface, lits.map((f) => decimal(surface, f.value)));
        const hexes: Record<string, string> = {};
        for (const tier of tiers) {
          const h = hexOf(tier, test, file);
          expect(h, `${tier.id}: ${lits.map((f) => f.lit).join(' ')}`).toBe(hexOf(tier, control, file));
          hexes[tier.id] = h;
        }
        expect(new Set(Object.values(hexes)).size, JSON.stringify(hexes)).toBe(1);
      };
      check(positive, available);
      const wide = all.filter(n028);
      if (wide.length > 0) check(wide, available.filter((t) => t.id !== 'rust'));

      if (negative.length > 0) {
        const neg = contract(surface, negative.map((f) => f.lit));
        const negHex: Record<string, string> = {};
        for (const tier of available) negHex[tier.id] = hexOf(tier, neg, file);
        expect(new Set(Object.values(negHex)).size, JSON.stringify(negHex)).toBe(1);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Execution oracle (attempt 1's proof, kept): @bsv/sdk Spend.validate.
// ---------------------------------------------------------------------------

const req = createRequire(join(REPO, 'packages/runar-testing/package.json'));
const { Spend, LockingScript, UnlockingScript } = req('@bsv/sdk');

function spends(lock: string, unlock: string): boolean {
  const spend = new Spend({
    sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 100000,
    // F-055: version 1 + isRelaxed false, the strict rule set an SDK-built (v1)
    // tx faces; version 2 put Spend in relaxed mode.
    lockingScript: LockingScript.fromHex(lock), transactionVersion: 1, otherInputs: [], outputs: [],
    unlockingScript: UnlockingScript.fromHex(unlock), inputIndex: 0, inputSequence: 0xffffffff, lockTime: 0,
    isRelaxed: false,
  });
  try {
    return spend.validate();
  } catch {
    return false;
  }
}

const EXPLOIT_ZIG = (lit: string) => `const runar = @import("runar");

pub const T = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) T {
        return .{ .target = target };
    }

    pub fn verify(self: *const T, amount: i64, b1010: runar.ByteString) void {
        _ = self;
        runar.assert(amount > ${lit});
    }
};
`;

/** Pre-fix reference-tier artifact of EXPLOIT_ZIG('0b1010'): `amount > 0`. */
const PRE_FIX_LOCK = '7c00a077';
/** unlocking scripts: push amount, push b1010 = 0xab */
const AMOUNT_5 = '5501ab';
const AMOUNT_11 = '5b01ab';

describe('F-026 execution oracle: the exploit shape now guards `> 10`', () => {
  it('the pre-fix artifact accepted amount = 5 (the defect, kept as evidence)', () => {
    expect(spends(PRE_FIX_LOCK, AMOUNT_5)).toBe(true);
  });

  it('every tier compiles `0b1010` to the `10` script, which rejects 5 and accepts 11', () => {
    const reference = hexOf(TIERS.find((t) => t.id === 'ts')!, EXPLOIT_ZIG('10'), 'X.runar.zig');
    expect(spends(reference, AMOUNT_5)).toBe(false);
    expect(spends(reference, AMOUNT_11)).toBe(true);
    for (const tier of available) {
      const lock = hexOf(tier, EXPLOIT_ZIG('0b1010'), 'X.runar.zig');
      expect(lock, tier.id).toBe(reference);
      expect(spends(lock, AMOUNT_5), `${tier.id} amount=5`).toBe(false);
      expect(spends(lock, AMOUNT_11), `${tier.id} amount=11`).toBe(true);
    }
  });
});
