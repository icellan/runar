import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

function errorsOf(src: string, fileName = 'X.runar.ts'): string[] {
  const r = compile(src, { fileName });
  return (r.diagnostics ?? []).filter((d) => d.severity === 'error').map((d) => d.message);
}
function warningsOf(src: string, fileName = 'X.runar.ts'): string[] {
  const r = compile(src, { fileName });
  return (r.diagnostics ?? []).filter((d) => d.severity === 'warning').map((d) => d.message);
}
function compiles(src: string, fileName = 'X.runar.ts'): boolean {
  const r = compile(src, { fileName });
  return !!r.artifact && (r.diagnostics ?? []).filter((d) => d.severity === 'error').length === 0;
}

// ---------------------------------------------------------------------------
// Negative: one rejection per validation rule
// ---------------------------------------------------------------------------

describe('#123 field-usage validation — ANYONECANPAY', () => {
  const GUARD = (directive: string) => `
    class Guard extends SmartContract {
      readonly expected: ByteString;
      constructor(expected: ByteString) { super(expected); this.expected = expected; }
      ${directive}
      public spend(pre: SigHashPreimage): void {
        assert(checkPreimage(pre));
        assert(extractHashPrevouts(pre) === this.expected);
      }
    }`;

  it('rejects extractHashPrevouts under ANYONECANPAY', () => {
    const errs = errorsOf(GUARD('/** @sighash ALL|ANYONECANPAY|FORKID */'));
    expect(errs.some((e) => /hashPrevouts.*zeroed under ANYONECANPAY/.test(e))).toBe(true);
  });

  it('rejects extractPrevOutputScript (companion-input) under ANYONECANPAY', () => {
    const src = `
      class Co extends StatefulSmartContract {
        readonly h0: ByteString;
        n: bigint;
        constructor(h0: ByteString, n: bigint) { super(h0, n); this.h0 = h0; this.n = n; }
        /** @sighash ALL|ANYONECANPAY|FORKID */
        public coSpend(): void {
          const s = extractPrevOutputScript(1n, this.h0);
          assert(len(s) > 0n);
        }
      }`;
    expect(errorsOf(src).some((e) => /companion input|prevout script/.test(e))).toBe(true);
  });

  it('ACCEPTS the same extractHashPrevouts read under the ALL default', () => {
    expect(compiles(GUARD(''))).toBe(true);
    expect(compiles(GUARD('/** @sighash ALL|FORKID */'))).toBe(true);
  });
});

describe('#123 field-usage validation — NONE', () => {
  it('rejects a state continuation under NONE', () => {
    const src = `
      class Counter extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash NONE|FORKID */
        public bump(): void { this.n = this.n + 1n; }
      }`;
    expect(errorsOf(src).some((e) => /NONE commits to NO outputs|continuation/.test(e))).toBe(true);
  });

  it('ACCEPTS the same mutation under the ALL default', () => {
    const src = `
      class Counter extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        public bump(): void { this.n = this.n + 1n; }
      }`;
    expect(compiles(src)).toBe(true);
  });
});

describe('#123 field-usage validation — SINGLE', () => {
  it('rejects a multi-output (non-same-index) continuation under SINGLE', () => {
    const src = `
      class Multi extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        /** @sighash SINGLE|FORKID */
        public split(): void {
          this.addOutput(1000n, this.count);
          this.addOutput(2000n, this.count);
        }
      }`;
    expect(errorsOf(src).some((e) => /SINGLE commits ONLY to the output at this input/.test(e))).toBe(true);
  });

  // F1 (P1): the mutate-only auto-continuation is value-skimmable under SINGLE.
  //
  // Skim scenario (why this REJECT exists): `bump()` mutates state only, so the
  // compiler auto-injects ONE continuation output whose satoshi value is the
  // caller-supplied `_newAmount`. Under BIP-143 SINGLE the sighash commits ONLY
  // to the output at THIS input's index and does NOT pin its value. A malicious
  // spender therefore calls bump with _newAmount = dust, sets `_changeAmount`
  // (change) to 0, and APPENDS a draining output that sweeps the difference to
  // themselves. The covenant + OP_PUSH_TX binding still validate (they only see
  // the same-index continuation), so the protected funds are stolen. Conversely
  // an honest change>0 leaves the UTXO unspendable. The mode is unsound — reject.
  // D25: the #123 (F1) refusal predated the F-024 `_newAmount` floor and
  // N-038; SINGLE hashes the whole same-index output, value included, so a
  // mutate-only SINGLE continuation is sound (and the default for a contract
  // whose continuation methods are all mutate-only).
  it('ACCEPTS a mutate-only auto-continuation under SINGLE (the F-024 floor pins its value)', () => {
    const src = `
      class Counter extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        public bump(): void { this.n = this.n + 1n; }
      }`;
    expect(errorsOf(src)).toEqual([]);
    expect(compiles(src)).toBe(true);
  });

  // F1 (P1): the legitimate pairwise input↔output covenant — exactly one
  // explicit addOutput carrying the protected value at this input's index — is
  // ALLOWED, but warns that SINGLE cannot statically pin the amount.
  it('ACCEPTS an explicit single addOutput under SINGLE, with a value-pinning WARNING', () => {
    const src = `
      class Pay extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        public settle(): void { this.addOutput(1000n, this.n); }
      }`;
    expect(compiles(src)).toBe(true);
    expect(warningsOf(src).some((w) =>
      /SINGLE commits ONLY to the output at this input|carries the FULL protected value/.test(w),
    )).toBe(true);
  });

  it('ACCEPTS the same mutate-only method under the ALL default', () => {
    const src = `
      class Counter extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        public bump(): void { this.n = this.n + 1n; }
      }`;
    expect(compiles(src)).toBe(true);
  });

  it('ACCEPTS the same multi-output method under the ALL default', () => {
    const src = `
      class Multi extends StatefulSmartContract {
        count: bigint;
        constructor(count: bigint) { super(count); this.count = count; }
        public split(): void {
          this.addOutput(1000n, this.count);
          this.addOutput(2000n, this.count);
        }
      }`;
    expect(compiles(src)).toBe(true);
  });

  // F4 (P2): requireOutputP2PKH asserts an output at a FIXED index, which cannot
  // be proven equal to THIS input's index — the only output SINGLE commits to.
  it('REJECTS requireOutputP2PKH under SINGLE (fixed-index output not provably same-index)', () => {
    const src = `
      class Cov extends StatefulSmartContract {
        readonly bondPKH: ByteString;
        readonly bond: bigint;
        constructor(bondPKH: ByteString, bond: bigint) { super(bondPKH, bond); this.bondPKH = bondPKH; this.bond = bond; }
        /** @sighash SINGLE|FORKID */
        public payBond() { requireOutputP2PKH(0n, this.bondPKH, this.bond); }
      }`;
    expect(errorsOf(src).some((e) =>
      /'requireOutputP2PKH' asserts an output at a fixed index.*SINGLE/.test(e),
    )).toBe(true);
  });

  it('ACCEPTS the same requireOutputP2PKH covenant under the ALL default', () => {
    const src = `
      class Cov extends StatefulSmartContract {
        readonly bondPKH: ByteString;
        readonly bond: bigint;
        constructor(bondPKH: ByteString, bond: bigint) { super(bondPKH, bond); this.bondPKH = bondPKH; this.bond = bond; }
        public payBond() { requireOutputP2PKH(0n, this.bondPKH, this.bond); }
      }`;
    expect(compiles(src)).toBe(true);
  });
});

// F3 (P2): the transitive field-read walk must cover the for-loop header
// (init + condition) and the assignment target, not only update/body/value.
describe('#123 field-usage validation — transitive walk (F3)', () => {
  it('rejects a hashOutputs read hidden in a for-loop CONDITION under NONE', () => {
    // extractOutputHash lives ONLY in the loop condition. Before the walk fix
    // the condition was never visited, so this unsound read slipped through.
    // (The loop also trips the compile-time-bound check; we assert specifically
    //  that the sighash rejection is present.)
    const src = `
      class C extends SmartContract {
        readonly expected: ByteString;
        constructor(expected: ByteString) { super(expected); this.expected = expected; }
        /** @sighash NONE|FORKID */
        public spend(pre: SigHashPreimage): void {
          for (let i = 0n; i < 3n && extractOutputHash(pre) === this.expected; i++) { assert(i < 2n); }
          assert(checkPreimage(pre));
        }
      }`;
    expect(errorsOf(src).some((e) => /hashOutputs.*zeroed under NONE/.test(e))).toBe(true);
  });
});
