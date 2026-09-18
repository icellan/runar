/**
 * N-099 — a ternary whose two arms have incompatible types.
 *
 *     const y: ByteString = f ? this.blob : x;   // blob: ByteString, x: bigint
 *
 * TypeScript is the reference here and already refuses it. Measured across the
 * seven tiers before the fix:
 *
 *     ts / rust / java          REJECT
 *     go / python / zig / ruby  ACCEPT, 12 hexchars
 *
 * The four permissive tiers silently take the CONSEQUENT's type as the
 * expression's type. A ByteString and a bigint do not share a stack
 * representation — one is a byte string, the other a script number — so the arm
 * that was silently retyped leaves the wrong kind of value on the stack and
 * everything downstream reads a type the author never wrote. Same class as the
 * operand-position `<unknown>` escapes R-092 closed: a 33-byte push into an
 * arithmetic opcode succeeds post-Genesis and computes something meaningless
 * instead of failing.
 *
 * The four tiers already had the exact subtype fall-through this rule needs —
 * `isSubtype(alt, cons) || isSubtype(cons, alt)` — they just returned the
 * consequent type from it instead of raising.
 *
 * This file is the reference tier's regression guard, and the ACCEPT block is
 * the contract every port must satisfy: identical arms, a declared subtype
 * pair, and an `<unknown>` arm (top of the lattice) all stay legal.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const HEAD = `import { SmartContract, ByteString, Ripemd160, assert, hash160 } from 'runar-lang';

class C extends SmartContract {
  readonly pkh: Ripemd160;
  readonly blob: ByteString;

  constructor(pkh: Ripemd160, blob: ByteString) {
    super(pkh, blob);
    this.pkh = pkh;
    this.blob = blob;
  }

  private anySats(): bigint { return 1n; }

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

const MIXED_ARMS = contract(`  public go(x: bigint, f: boolean) {
    const y: ByteString = f ? this.blob : x;
    assert(y == this.blob);
  }
`);

/** The mirror image — bigint consequent, ByteString alternate. A rule that
 *  only looked one way would let this through. */
const MIXED_ARMS_SWAPPED = contract(`  public go(x: bigint, f: boolean) {
    const y: bigint = f ? x : this.blob;
    assert(y > 0n);
  }
`);

const SAME_TYPE_ARMS = contract(`  public go(x: bigint, f: boolean) {
    const a: bigint = f ? x : 2n;
    assert(a > 0n);
  }
`);

/** `Ripemd160` is a declared subtype of `ByteString`; `isSubtype` relates them
 *  in both directions and the rule must not fire. */
const SUBTYPE_ARMS = contract(`  public go(x: bigint, f: boolean) {
    const b: ByteString = f ? this.blob : this.pkh;
    assert(hash160(b) != this.pkh || x > 0n);
  }
`);

/** A private helper's declared return type is discarded at parse time in EVERY
 *  tier, so this arm infers as `<unknown>` — top of the subtype lattice, hence
 *  related to everything. Must stay ACCEPTED. */
const UNKNOWN_ARM = contract(`  public go(x: bigint, f: boolean) {
    const c: bigint = f ? this.anySats() : x;
    assert(c > 0n);
  }
`);

describe('N-099: incompatible ternary arms', () => {
  it('rejects a ByteString consequent against a bigint alternate', () => {
    expect(errorsOf(MIXED_ARMS)).toContain(
      "Ternary branches have incompatible types: 'ByteString' and 'bigint'",
    );
  });

  it('rejects the swapped shape too', () => {
    expect(errorsOf(MIXED_ARMS_SWAPPED)).toContain(
      "Ternary branches have incompatible types: 'bigint' and 'ByteString'",
    );
  });
});

describe('N-099: ternary arms that must stay ACCEPTED', () => {
  it('identical arm types', () => {
    expect(errorsOf(SAME_TYPE_ARMS)).toEqual([]);
  });

  it('a declared subtype pair (ByteString / Ripemd160)', () => {
    expect(errorsOf(SUBTYPE_ARMS)).toEqual([]);
  });

  it("an arm inferred as '<unknown>' (a private helper's return type)", () => {
    expect(errorsOf(UNKNOWN_ARM)).toEqual([]);
  });
});
