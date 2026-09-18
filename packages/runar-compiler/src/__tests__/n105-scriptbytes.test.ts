/**
 * N-105 (1/2) — a NUMBER in the scriptBytes position of addRawOutput /
 * addDataOutput.
 *
 * Same shape as N-098, one argument slot over, and the slot is the created
 * output's LOCKING SCRIPT.
 *
 * TypeScript is the reference here and already refuses it. The other six tiers
 * accepted `this.addRawOutput(1000n, n)` with `n: bigint`, and the emitted
 * script was byte-identical to the same contract written with `n: ByteString` —
 * measured through all six, same digest. The operand is not converted: whatever
 * sits in that slot is spliced into the output serialization as the output's
 * script.
 *
 * `lowerAddRawOutput` takes OP_SIZE of the operand, varint-prefixes it and
 * concatenates it after the 8-byte amount. A script NUMBER on the stack is its
 * minimal little-endian encoding, so the covenant commits to an output whose
 * locking script IS those bytes. Executed on the real `@bsv/sdk` Spend engine
 * against the exact 55-opcode window all six tiers emit:
 *
 *   n=0     -> scriptLen 0   locking script (empty)     — anyone-can-spend
 *   n=81    -> scriptLen 1   0x51 = OP_1                — anyone-can-spend
 *   n=118   -> scriptLen 1   0x76 = OP_DUP              — anyone-can-spend
 *   n=1000  -> scriptLen 2   0xe8 0x03, 0xe8 invalid    — unspendable
 *
 * N-098's failure mode was a wrong amount or a frozen UTXO. This one can hand
 * the whole output to anybody who sees it, which is why it is a gate.
 *
 * This file is the reference tier's regression guard for a check that already
 * exists — the six ports (`compilers/*`) each pin the same wording and the same
 * ACCEPT set, which is what makes it a parity gate rather than six independent
 * opinions. The ACCEPT cases matter as much as the REJECT ones: `<unknown>`
 * (a private helper's return type, which no tier derives) must stay ACCEPTED,
 * and so must every ByteString SUBTYPE, exactly as TS has always had it.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const HEAD = `import { StatefulSmartContract, ByteString, Ripemd160, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  readonly base: bigint;
  readonly flag: boolean;
  readonly blob: ByteString;
  readonly pkh: Ripemd160;

  constructor(count: bigint, base: bigint, flag: boolean, blob: ByteString, pkh: Ripemd160) {
    super(count, base, flag, blob, pkh);
    this.count = count;
    this.base = base;
    this.flag = flag;
    this.blob = blob;
    this.pkh = pkh;
  }

  private bytes(): ByteString { return this.blob; }

`;

function contract(body: string): string {
  return `${HEAD}${body}}\n`;
}

function errorsOf(source: string): string[] {
  const r = compile(source, { fileName: 'C.runar.ts' });
  return (r.diagnostics ?? [])
    .filter((d) => d.severity === 'error')
    .map((d) => d.message);
}

function hexOf(source: string): string {
  const r = compile(source, { fileName: 'C.runar.ts' });
  const errs = (r.diagnostics ?? []).filter((d) => d.severity === 'error');
  expect(errs.map((d) => d.message), 'expected this contract to compile').toEqual([]);
  return r.artifact!.script;
}

// ---------------------------------------------------------------------------
// REJECT — the finding
// ---------------------------------------------------------------------------

const RAW_BIGINT_SCRIPT = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.base);
  }
`);

const DATA_BIGINT_SCRIPT = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(500n, this.base);
  }
`);

const RAW_BOOLEAN_SCRIPT = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.flag);
  }
`);

// ---------------------------------------------------------------------------
// ACCEPT — the over-rejection guards
// ---------------------------------------------------------------------------

const RAW_BYTESTRING_SCRIPT = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.blob);
  }
`);

const RAW_STATE_SCRIPT = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.getStateScript());
  }
`);

/** TS's rule is isSubtype(scriptType, ByteString), not equality. */
const RAW_SUBTYPE_SCRIPT = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.pkh);
  }
`);

/** A private helper's declared return type is discarded at parse time in EVERY
 *  tier (`MethodNode` carries no `returnType`), so this infers as `<unknown>`. */
const RAW_HELPER_SCRIPT = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.bytes());
  }
`);

const DATA_BYTESTRING_SCRIPT = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(500n, this.blob);
  }
`);

describe('N-105: a non-ByteString in the scriptBytes position', () => {
  it('addRawOutput rejects a bigint second argument', () => {
    expect(errorsOf(RAW_BIGINT_SCRIPT)).toContain(
      "addRawOutput() second argument (scriptBytes) must be ByteString, got 'bigint'",
    );
  });

  it('addDataOutput rejects a bigint second argument', () => {
    expect(errorsOf(DATA_BIGINT_SCRIPT)).toContain(
      "addDataOutput() second argument (scriptBytes) must be ByteString, got 'bigint'",
    );
  });

  it('addRawOutput rejects a boolean second argument', () => {
    expect(errorsOf(RAW_BOOLEAN_SCRIPT)).toContain(
      "addRawOutput() second argument (scriptBytes) must be ByteString, got 'boolean'",
    );
  });

  /**
   * The reason the six tiers' output was indistinguishable from a correct
   * program: they emitted the SAME bytes for `n: bigint` and `n: ByteString`.
   * A rule that only removes the bad program must leave the good one alone.
   */
  it('the rejected source is not merely a lint — the ByteString twin compiles', () => {
    expect(errorsOf(RAW_BIGINT_SCRIPT).length).toBeGreaterThan(0);
    expect(errorsOf(RAW_BYTESTRING_SCRIPT)).toEqual([]);
  });
});

describe('N-105: scriptBytes positions that must stay ACCEPTED', () => {
  it('a ByteString property', () => {
    expect(hexOf(RAW_BYTESTRING_SCRIPT).length).toBeGreaterThan(0);
  });

  it('getStateScript()', () => {
    expect(hexOf(RAW_STATE_SCRIPT).length).toBeGreaterThan(0);
  });

  it('a ByteString subtype (Ripemd160)', () => {
    expect(hexOf(RAW_SUBTYPE_SCRIPT).length).toBeGreaterThan(0);
  });

  it("a private helper call, whose return type infers as '<unknown>'", () => {
    expect(hexOf(RAW_HELPER_SCRIPT).length).toBeGreaterThan(0);
  });

  it('addDataOutput with a ByteString property', () => {
    expect(hexOf(DATA_BYTESTRING_SCRIPT).length).toBeGreaterThan(0);
  });

  /**
   * Non-vacuity: "it compiled" would also be true of a tier that silently
   * discarded the scriptBytes operand. Two different ByteString operands must
   * lower to DIFFERENT scripts. Every tier's own N-105 test asserts this.
   */
  it('the scriptBytes operand actually reaches codegen', () => {
    expect(hexOf(RAW_BYTESTRING_SCRIPT)).not.toEqual(hexOf(RAW_STATE_SCRIPT));
  });
});
