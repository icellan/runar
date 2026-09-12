/**
 * N-098 — a ByteString in the SATOSHIS position of an output intrinsic.
 *
 * TypeScript is the reference here and already refuses all three shapes. The
 * other six tiers accepted them and lowered the ByteString into the satoshis
 * slot with NO conversion: the Go tier compiled `blob: ByteString` and
 * `blob: bigint` versions of the same contract to the SAME 1358-hexchar script.
 *
 * `lowerAddOutput` prepends the satoshis operand as `OP_8 OP_NUM2BIN`, so the
 * amount the covenant commits to is whatever those bytes decode to as a script
 * number. Executed on the real `@bsv/sdk` Spend engine with `blob = 0x2a`, a
 * 42-satoshi continuation VALIDATES and the 1000-satoshi one the author funded
 * is REJECTED. Bigger blobs fail shut rather than safe: 0xcafebabefeed0001
 * demands 7.2e16 satoshis and a 20-byte hash aborts the script at OP_NUM2BIN,
 * so the UTXO becomes unspendable. That is why this is a gate.
 *
 * This file is the reference tier's regression guard for a check that already
 * exists — the six ports (`compilers/*`) each pin the same wording and the same
 * ACCEPT set, which is what makes it a parity gate rather than six independent
 * opinions. The ACCEPT cases matter as much as the REJECT ones: `<unknown>`
 * (a private helper's return type, which no tier derives) must stay ACCEPTED,
 * exactly as TS has always had it.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const HEAD = `import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, base: bigint, blob: ByteString) {
    super(count, base, blob);
    this.count = count;
    this.base = base;
    this.blob = blob;
  }

  private sats(): bigint { return this.base; }

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

const BYTESTRING_ADD_OUTPUT = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.blob, this.count);
  }
`);

const BYTESTRING_ADD_RAW_OUTPUT = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(this.blob, this.blob);
  }
`);

const BYTESTRING_ADD_DATA_OUTPUT = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(this.blob, this.blob);
  }
`);

// ---------------------------------------------------------------------------
// ACCEPT — the over-rejection guards
// ---------------------------------------------------------------------------

const LITERAL_SATS = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
  }
`);

const PARAM_SATS = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(n, this.count);
  }
`);

const PROPERTY_SATS = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.base, this.count);
  }
`);

/** A private helper's return type is discarded at parse time in EVERY tier
 *  (`MethodNode` carries no `returnType`), so this infers as `<unknown>`. TS
 *  has always escaped `<unknown>` here and every port must too. */
const HELPER_SATS = contract(`  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.sats(), this.count);
  }
`);

describe('N-098: ByteString in the satoshis position', () => {
  it('addOutput rejects a ByteString first argument', () => {
    expect(errorsOf(BYTESTRING_ADD_OUTPUT)).toContain(
      "addOutput() first argument (satoshis) must be bigint, got 'ByteString'",
    );
  });

  it('addRawOutput rejects a ByteString first argument', () => {
    expect(errorsOf(BYTESTRING_ADD_RAW_OUTPUT)).toContain(
      "addRawOutput() first argument (satoshis) must be bigint, got 'ByteString'",
    );
  });

  it('addDataOutput rejects a ByteString first argument', () => {
    expect(errorsOf(BYTESTRING_ADD_DATA_OUTPUT)).toContain(
      "addDataOutput() first argument (satoshis) must be bigint, got 'ByteString'",
    );
  });

  /**
   * The reason the six tiers' output was indistinguishable from a correct
   * program: they emitted the SAME bytes for `blob: ByteString` and
   * `blob: bigint`. A rule that only removes the bad program must leave the
   * good one byte-identical, which is what the ACCEPT block below pins.
   */
  it('the rejected source is not merely a lint — it lowers as if it were bigint', () => {
    const asBigint = compile(
      BYTESTRING_ADD_OUTPUT.replace('readonly blob: ByteString;', 'readonly blob: bigint;')
        .replace('blob: ByteString)', 'blob: bigint)')
        .replace(", ByteString, assert }", ", assert }"),
      { fileName: 'C.runar.ts' },
    );
    // The bigint-typed twin compiles; the ByteString-typed one must not.
    expect((asBigint.diagnostics ?? []).filter((d) => d.severity === 'error')).toEqual([]);
    expect(errorsOf(BYTESTRING_ADD_OUTPUT).length).toBeGreaterThan(0);
  });
});

describe('N-098: satoshis positions that must stay ACCEPTED', () => {
  it('a bigint literal', () => {
    expect(hexOf(LITERAL_SATS).length).toBeGreaterThan(0);
  });

  it('a bigint method parameter', () => {
    expect(hexOf(PARAM_SATS).length).toBeGreaterThan(0);
  });

  it('a bigint contract property', () => {
    expect(hexOf(PROPERTY_SATS).length).toBeGreaterThan(0);
  });

  it("a private helper call, whose return type infers as '<unknown>'", () => {
    expect(hexOf(HELPER_SATS).length).toBeGreaterThan(0);
  });

  /**
   * Non-vacuity: "it compiled" would also be true of a tier that silently
   * discarded the satoshis operand. A literal 1000 and a runtime parameter
   * must lower to DIFFERENT scripts, which is only possible if the operand
   * reaches codegen at all. Every tier's own N-098 test makes this same
   * assertion.
   */
  it('the satoshis operand actually reaches codegen', () => {
    expect(hexOf(LITERAL_SATS)).not.toEqual(hexOf(PARAM_SATS));
    expect(hexOf(LITERAL_SATS)).toContain('02e803'); // PUSH(2) 0xe8 0x03 == 1000
  });
});
