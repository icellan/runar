/**
 * R-095 — the `SIZE(_codePart)` pin must agree with what the SDK actually
 * deploys.
 *
 * `emitCodePartAuthentication` pins the split point between the code part and
 * the `OP_RETURN || state` section. With a fixed-size state layout the pin
 * rides on the REMAINDER's length (clause 8a). With a ByteString state field
 * there is no compile-time remainder length, so the pin rides on the code
 * part's own DEPLOYED byte length instead — a number the compiler bakes into
 * the script from the emitted template length plus the type-determined growth
 * of the constructor-arg placeholders.
 *
 * That number is load-bearing in BOTH directions:
 *
 *  - too small, and a spender can still claim a truncated code part and
 *    redirect the contract's satoshis (the hole R-095 closes);
 *  - too large, and every honest spend fails OP_VERIFY — the contract's funds
 *    are unspendable.
 *
 * The compiler computes it from `constructorSlots` metadata; the SDK computes
 * the real thing by splicing actual args. This file is the oracle that keeps
 * those two derivations equal. It is deliberately in the SDK package: the
 * compiler alone cannot see the deployed script.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { RunarContract } from '../contract.js';

const OWNER = '02' + '11'.repeat(32);
const ISSUER = '03' + '22'.repeat(32);

/** One decoded `verify_code_part_len` pin. */
interface DecodedPin {
  /** Byte offset of the OP_DUP that opens the sequence. */
  byteOffset: number;
  /** true → OP_NUMEQUAL (exact); false → OP_GREATERTHANOREQUAL (lower bound). */
  exact: boolean;
  /** The pinned deployed code-part length. */
  value: number;
}

/**
 * Find every pin in a compiled script.
 *
 * The sequence is fixed-width and unambiguous:
 *
 *   76 | 04 LL LL LL LL | 81 | (9c|a2) | 69
 *
 * Matching on the full shape rather than on `7604` alone keeps an ordinary
 * 4-byte data push that happens to follow an OP_DUP from being mistaken for
 * a pin.
 */
function decodePins(scriptHex: string): DecodedPin[] {
  const pins: DecodedPin[] = [];
  for (let i = 0; i + 18 <= scriptHex.length; i += 2) {
    const seq = scriptHex.slice(i, i + 18);
    if (!seq.startsWith('7604')) continue;
    if (seq.slice(12, 14) !== '81') continue;
    const cmp = seq.slice(14, 16);
    if (cmp !== '9c' && cmp !== 'a2') continue;
    if (seq.slice(16, 18) !== '69') continue;
    const le = seq.slice(4, 12);
    const value = parseInt(le.match(/../g)!.reverse().join(''), 16);
    pins.push({ byteOffset: i / 2, exact: cmp === '9c', value });
  }
  return pins;
}

function compileOrThrow(source: string, fileName: string) {
  const r = compile(source, { fileName });
  if (!r.artifact || !r.scriptHex) {
    throw new Error(`compile failed: ${JSON.stringify(r.diagnostics)}`);
  }
  return r;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * Variable-length state, and every readonly constructor param is a
 * fixed-width type. The compiler knows the deployed growth exactly, so the
 * pin must be an EQUALITY pin whose value is the deployed code length.
 */
const VARLEN_FIXED_CTOR = `
import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

class VarLenFixedCtor extends StatefulSmartContract {
  memo: ByteString;
  readonly owner: PubKey;

  constructor(memo: ByteString, owner: PubKey) {
    super(memo, owner);
    this.memo = memo;
    this.owner = owner;
  }

  public post(newMemo: ByteString) {
    this.memo = newMemo;
  }

  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }
}
`;

/**
 * Variable-length state and NO readonly params at all — no constructor slots,
 * so the template length IS the deployed length.
 */
const VARLEN_NO_CTOR_SLOTS = `
import { StatefulSmartContract } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class VarLenNoSlots extends StatefulSmartContract {
  memo: ByteString;

  constructor(memo: ByteString) {
    super(memo);
    this.memo = memo;
  }

  public post(newMemo: ByteString) {
    this.memo = newMemo;
  }
}
`;

/**
 * Variable-length state plus a VARIABLE-width readonly param. The compiler
 * cannot know how many bytes `tag` bakes into, so the pin must degrade to a
 * sound LOWER bound rather than a wrong equality.
 */
const VARLEN_VARIABLE_CTOR = `
import { StatefulSmartContract, assert } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class VarLenVariableCtor extends StatefulSmartContract {
  memo: ByteString;
  readonly tag: ByteString;

  constructor(memo: ByteString, tag: ByteString) {
    super(memo, tag);
    this.memo = memo;
    this.tag = tag;
  }

  public post(newMemo: ByteString) {
    assert(this.tag != '');
    this.memo = newMemo;
  }
}
`;

/** Fixed-size state — clause 8a still covers it, so NO pin may be emitted. */
const FIXED_STATE = `
import { StatefulSmartContract } from 'runar-lang';

class FixedState extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count = this.count + 1n;
  }
}
`;

// ---------------------------------------------------------------------------

describe('R-095 code-part length pin', () => {
  it('an exact pin equals the length the SDK actually deploys', () => {
    const r = compileOrThrow(VARLEN_FIXED_CTOR, 'VarLenFixedCtor.runar.ts');
    const pins = decodePins(r.scriptHex!);
    expect(pins.length).toBeGreaterThanOrEqual(1);

    const deployed = new RunarContract(r.artifact!, ['48656c6c6f', OWNER]).buildCodeScript();
    const deployedLen = deployed.length / 2;

    for (const pin of pins) {
      expect(pin.exact).toBe(true);
      // Equality, not "close enough": a pin one byte off makes every honest
      // spend fail OP_VERIFY and locks the contract's funds forever.
      expect(pin.value).toBe(deployedLen);
    }
  });

  it('the pin is invariant to the VALUE of a fixed-width readonly arg', () => {
    const r = compileOrThrow(VARLEN_FIXED_CTOR, 'VarLenFixedCtor.runar.ts');
    const pin = decodePins(r.scriptHex!)[0]!;
    for (const owner of [OWNER, ISSUER]) {
      const deployed = new RunarContract(r.artifact!, ['00', owner]).buildCodeScript();
      expect(pin.value).toBe(deployed.length / 2);
    }
  });

  it('with no constructor slots the pin is the template length itself', () => {
    const r = compileOrThrow(VARLEN_NO_CTOR_SLOTS, 'VarLenNoSlots.runar.ts');
    const pins = decodePins(r.scriptHex!);
    expect(pins.length).toBeGreaterThanOrEqual(1);
    const deployedLen = new RunarContract(r.artifact!, ['48656c6c6f'])
      .buildCodeScript().length / 2;
    for (const pin of pins) {
      expect(pin.exact).toBe(true);
      expect(pin.value).toBe(deployedLen);
      expect(pin.value).toBe(r.scriptHex!.length / 2);
    }
  });

  it('a variable-width readonly arg degrades the pin to a sound lower bound', () => {
    const r = compileOrThrow(VARLEN_VARIABLE_CTOR, 'VarLenVariableCtor.runar.ts');
    const pins = decodePins(r.scriptHex!);
    expect(pins.length).toBeGreaterThanOrEqual(1);

    // Two very different tag lengths: the pin cannot be exact for both, and
    // must be <= the deployed length for BOTH or an honest spend breaks.
    for (const tag of ['aa', 'bb'.repeat(64)]) {
      const deployedLen = new RunarContract(r.artifact!, ['48656c6c6f', tag])
        .buildCodeScript().length / 2;
      for (const pin of pins) {
        expect(pin.exact).toBe(false);
        expect(pin.value).toBeLessThanOrEqual(deployedLen);
      }
    }
  });

  it('a fixed-size state layout emits no pin at all (clause 8a still covers it)', () => {
    const r = compileOrThrow(FIXED_STATE, 'FixedState.runar.ts');
    expect(decodePins(r.scriptHex!)).toEqual([]);
  });
});
