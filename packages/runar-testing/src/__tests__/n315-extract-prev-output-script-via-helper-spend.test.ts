/**
 * N-315 — `extractPrevOutputScript` called from a private helper must compile,
 * and the compiled script must enforce exactly what the direct call enforces.
 *
 * The intrinsic auto-injects a `_prevOutScript_<i>` witness param into the
 * method it is lowered in. ANF lowering inlined a private helper at the call
 * site only when the helper emitted outputs or (N-070) called
 * `requireOutputP2PKH`, so a helper that called `extractPrevOutputScript`
 * stayed a `method_call`: the witness param landed on the helper's own ANF
 * method, never on the public spending method, and stack lowering refused the
 * program ("method parameter '_prevOutScript_0' is not on the stack").
 *
 * ORACLE. `@bsv/sdk`'s production `Spend` interpreter — never `TestContract`,
 * which shares the compiler's model. The contract is stateless so the unlock is
 * the witness alone and no preimage harness is involved; the intrinsic's
 * check (hash256 of the witness equals the committed hash) does not read the
 * preimage in either the stateless or the stateful lowering.
 *
 * The helpers return the witness rather than being `void`: a stateless public
 * method must END with an assert, so a body of `this.checkBound();` is refused
 * by validation whatever the lowering does. The void-helper shape is covered,
 * stateful, by the cross-tier test.
 *
 * PROVES: a value-returning helper, called directly and through a second
 * helper, compiles, emits the SAME bytes as the direct form, puts
 * `_prevOutScript_0` on the public ABI, accepts the honest witness and rejects
 * a well-formed witness that hashes to something else.
 * DOES NOT PROVE: cross-tier agreement (tests/n315-extract-prev-output-script-
 * via-helper.test.ts does that against the seven-tier stateful golden), the
 * 3-arg prefix form through a helper, or anything about which input the
 * witness came from — the intrinsic never reads a vin (see the fixture's doc
 * comment), so neither does this test.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { LockingScript, UnlockingScript, Spend, Hash } from '@bsv/sdk';

/** The script bytes the spender must reveal: an ordinary P2PKH. */
const PREV_SCRIPT = '76a914' + 'aa'.repeat(20) + '88ac';
/** Same shape, different payee: well-formed, wrong hash. */
const OTHER_SCRIPT = '76a914' + 'cc'.repeat(20) + '88ac';

function hash256Hex(hex: string): string {
  return Buffer.from(Hash.hash256(Array.from(Buffer.from(hex, 'hex')))).toString('hex');
}

const EXPECTED_HASH = hash256Hex(PREV_SCRIPT);

const PREAMBLE = `
import { SmartContract, ByteString, assert, len, extractPrevOutputScript } from 'runar-lang';

class PrevScriptLock extends SmartContract {
  readonly expectedHash: ByteString = '${EXPECTED_HASH}';

  constructor() { super(); }
`;

const DIRECT_SOURCE = `${PREAMBLE}
  public unlock() {
    const s = extractPrevOutputScript(0n, this.expectedHash);
    assert(len(s) > 0n);
  }
}
`;

/** Only the intrinsic moved into a helper that returns the witness. */
const RETURN_HELPER_SOURCE = `${PREAMBLE}
  private boundScript(): ByteString {
    return extractPrevOutputScript(0n, this.expectedHash);
  }

  public unlock() {
    const s = this.boundScript();
    assert(len(s) > 0n);
  }
}
`;

/** The same, one helper further away: the inlining flag must be transitive. */
const NESTED_HELPER_SOURCE = `${PREAMBLE}
  private boundScriptInner(): ByteString {
    return extractPrevOutputScript(0n, this.expectedHash);
  }

  private boundScript(): ByteString {
    return this.boundScriptInner();
  }

  public unlock() {
    const s = this.boundScript();
    assert(len(s) > 0n);
  }
}
`;

function pushData(hex: string): string {
  const n = hex.length / 2;
  if (n === 0) return '00';
  if (n < 0x4c) return n.toString(16).padStart(2, '0') + hex;
  if (n <= 0xff) return '4c' + n.toString(16).padStart(2, '0') + hex;
  throw new Error('helper only covers pushes up to 255 bytes');
}

const TX_CONTEXT = {
  sourceTXID: '11'.repeat(32),
  sourceOutputIndex: 0,
  sourceSatoshis: 5000,
  transactionVersion: 2,
  otherInputs: [] as never[],
  inputIndex: 0,
  inputSequence: 0xffffffff,
  lockTime: 0,
  outputs: [] as never[],
};

function spend(lockingHex: string, witness: string): { accepted: boolean; error?: string } {
  try {
    const s = new Spend({
      ...TX_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(pushData(witness)),
    });
    return { accepted: s.validate() };
  } catch (e) {
    return { accepted: false, error: e instanceof Error ? e.message : String(e) };
  }
}

const direct = compile(DIRECT_SOURCE, { fileName: 'PrevScriptLock.runar.ts' });

describe('N-315: extractPrevOutputScript delegated to a private helper', () => {
  it('the direct form compiles and accepts the honest witness (harness check)', () => {
    expect(direct.success, JSON.stringify(direct.diagnostics)).toBe(true);
    const r = spend(direct.artifact!.script, PREV_SCRIPT);
    expect(r.error, r.error).toBeUndefined();
    expect(r.accepted).toBe(true);
  });

  for (const [label, source] of [
    ['returning helper', RETURN_HELPER_SOURCE],
    ['nested returning helper', NESTED_HELPER_SOURCE],
  ] as const) {
    const compiled = compile(source, { fileName: 'PrevScriptLock.runar.ts' });

    it(`${label}: compiles`, () => {
      const errors = (compiled.diagnostics ?? []).filter((d) => d.severity === 'error');
      expect(errors.map((e) => e.message)).toEqual([]);
      expect(compiled.artifact).toBeDefined();
    });

    it(`${label}: emits byte-identical script to the direct call`, () => {
      expect(compiled.artifact!.script).toBe(direct.artifact!.script);
    });

    it(`${label}: puts _prevOutScript_0 on the public method ABI`, () => {
      const m = compiled.artifact!.abi.methods.find((x) => x.name === 'unlock')!;
      expect(m.params.map((p) => p.name)).toEqual(['_prevOutScript_0']);
    });

    it(`${label}: ACCEPTS the honest witness on Spend`, () => {
      const r = spend(compiled.artifact!.script, PREV_SCRIPT);
      expect(r.error, r.error).toBeUndefined();
      expect(r.accepted).toBe(true);
    });

    it(`${label}: REJECTS a well-formed witness with the wrong hash`, () => {
      expect(spend(compiled.artifact!.script, OTHER_SCRIPT).accepted).toBe(false);
    });
  }
});
