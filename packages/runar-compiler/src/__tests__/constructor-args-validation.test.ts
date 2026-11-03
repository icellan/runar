/**
 * constructorArgs shape validation — `compile(opts.constructorArgs)` must
 * reject inputs that would silently bake nothing and emit placeholder
 * scripts that fail opaquely at runtime:
 *
 *  (a) positional arrays (natural guess, but keys match no property names)
 *  (b) keys that don't match any contract property (typos)
 *  (c) referenced readonly properties left unbaked after applying the args
 *  (d) values whose kind or byte width does not match the property's
 *      declared type (F-101)
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

// ---------------------------------------------------------------------------
// Contract sources
// ---------------------------------------------------------------------------

const HASH_LOCK_SOURCE = `
class HashLock extends SmartContract {
  readonly hashValue: Sha256;

  constructor(hashValue: Sha256) {
    super(hashValue);
    this.hashValue = hashValue;
  }

  public unlock(preimage: ByteString) {
    assert(sha256(preimage) === this.hashValue);
  }
}
`;

const TWO_PROP_SOURCE = `
class TwoProp extends SmartContract {
  readonly target: bigint;
  readonly unused: bigint;

  constructor(target: bigint, unused: bigint) {
    super(target, unused);
    this.target = target;
    this.unused = unused;
  }

  public check(x: bigint) {
    assert(x === this.target);
  }
}
`;

const HASH = 'aa'.repeat(32);

function errorMessages(result: ReturnType<typeof compile>): string {
  return result.diagnostics
    .filter((d) => d.severity === 'error')
    .map((d) => d.message)
    .join('\n');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('constructorArgs validation', () => {
  it('rejects a positional array with a diagnostic error', () => {
    const result = compile(HASH_LOCK_SOURCE, {
      // Positional array — the shape RunarContract/TestSmartContract take,
      // but NOT what compile() takes. Previously baked nothing silently.
      constructorArgs: [HASH] as unknown as Record<string, string>,
    });

    expect(result.success).toBe(false);
    expect(errorMessages(result)).toMatch(/positional array/i);
  });

  it('rejects keys that match no contract property', () => {
    const result = compile(HASH_LOCK_SOURCE, {
      constructorArgs: { hashVal: HASH }, // typo: hashValue
    });

    expect(result.success).toBe(false);
    const msgs = errorMessages(result);
    expect(msgs).toContain("'hashVal'");
    expect(msgs).toContain('hashValue');
  });

  it('rejects when a referenced readonly property remains unbaked', () => {
    const result = compile(TWO_PROP_SOURCE, {
      // 'target' is referenced by check() but not provided.
      constructorArgs: { unused: 1n },
    });

    expect(result.success).toBe(false);
    expect(errorMessages(result)).toMatch(/'target'.*placeholder/s);
  });

  it('accepts an unreferenced readonly property left unbaked', () => {
    // 'unused' is never referenced by a method — DCE eliminates it, so
    // leaving it unbaked is fine.
    const result = compile(TWO_PROP_SOURCE, {
      constructorArgs: { target: 42n },
    });

    expect(result.success).toBe(true);
    expect(result.scriptHex).toBeDefined();
  });

  it('accepts a complete named record (baked script, no slots)', () => {
    const result = compile(HASH_LOCK_SOURCE, {
      constructorArgs: { hashValue: HASH },
    });

    expect(result.success).toBe(true);
    expect(result.artifact!.script).toContain(HASH);
    const slots = result.artifact!.constructorSlots;
    expect(slots === undefined || slots.length === 0).toBe(true);
  });

  // F-101 — (d) type / width check. Before the fix every case below compiled
  // with success === true: `true` baked as OP_1 and `42n` as a 1-byte push
  // where HASH160's 20-byte output is compared (76a95188ac / 76a9012a88ac),
  // a 6-byte hex string baked as a 6-byte push — all unspendable, no
  // diagnostic. Proves: compile() refuses each mismatch and names the
  // property, its declared type and the expected shape. Does NOT prove
  // anything about the deploy-time SDK path (constructorSlots), which never
  // goes through constructorArgs.
  describe('rejects a value that does not match the property type (F-101)', () => {
    const p2pkh = (t: string) => `
class P2PKH extends SmartContract {
  readonly pubKeyHash: ${t};
  constructor(pubKeyHash: ${t}) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}`;
    const cases: [string, string, unknown, RegExp][] = [
      ['ByteString <- boolean', 'ByteString', true, /must be a hex string, got a boolean/],
      ['Addr <- boolean', 'Addr', true, /must be exactly 20 bytes of hex, got a boolean/],
      ['Addr <- bigint', 'Addr', 42n, /must be exactly 20 bytes of hex, got an integer/],
      ['Addr <- 6-byte hex', 'Addr', 'aabbccddeeff', /must be exactly 20 bytes of hex, got 6 bytes of hex/],
      ['Addr <- non-hex', 'Addr', 'zzzz-not-hex', /must be exactly 20 bytes of hex, got a non-hex string/],
      ['ByteString <- odd-length hex', 'ByteString', 'abc', /must be a hex string, got a non-hex string/],
    ];
    for (const [label, type, value, re] of cases) {
      it(label, () => {
        const result = compile(p2pkh(type), {
          constructorArgs: { pubKeyHash: value as string },
        });
        expect(result.success).toBe(false);
        const msgs = errorMessages(result);
        expect(msgs).toContain(`property 'pubKeyHash' (${type})`);
        expect(msgs).toMatch(re);
      });
    }

    it('bigint <- string / boolean <- bigint', () => {
      const flagged = `
class Flagged extends SmartContract {
  readonly target: bigint;
  readonly on: boolean;
  constructor(target: bigint, on: boolean) { super(target, on); this.target = target; this.on = on; }
  public check(x: bigint) { assert(this.on); assert(x === this.target); }
}`;
      const result = compile(flagged, {
        constructorArgs: { target: '2a' as unknown as bigint, on: 1n as unknown as boolean },
      });
      expect(result.success).toBe(false);
      const msgs = errorMessages(result);
      expect(msgs).toMatch(/property 'target' \(bigint\) must be an integer, got 1 bytes of hex/);
      expect(msgs).toMatch(/property 'on' \(boolean\) must be a boolean, got an integer/);
    });

    it('accepts correctly typed values of every family', () => {
      const ok = compile(p2pkh('Addr'), { constructorArgs: { pubKeyHash: 'AB'.repeat(20) } });
      expect(ok.success).toBe(true);
      const bs = compile(p2pkh('ByteString'), { constructorArgs: { pubKeyHash: '' } });
      expect(bs.success).toBe(true);
    });
  });

  it('still compiles placeholder artifacts when no constructorArgs given', () => {
    const result = compile(HASH_LOCK_SOURCE);
    expect(result.success).toBe(true);
    expect(result.artifact!.constructorSlots!.length).toBeGreaterThanOrEqual(1);
  });
});
