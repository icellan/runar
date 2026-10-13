/**
 * F-227 (CL-BUG-097) — the interpreter's `checkSig` answered `false` where the
 * compiled script ABORTS.
 *
 * `checkSig` lowers to a bare `OP_CHECKSIG`. On `@bsv/sdk` `Spend`, that
 * opcode first runs `checkSignatureEncoding` and `checkPublicKeyEncoding`, and
 * either one failing ends the whole script with an evaluation error — it does
 * not push false. The interpreter instead returned `false` for anything it
 * could not decode, which is invisible under `assert(checkSig(...))` (both
 * reject) but not under `checkSig(a, A) || checkSig(b, B)` or an `if`/`else`
 * on a `checkSig`: the interpreter took the other arm and ACCEPTED a spend the
 * chain aborts on.
 *
 * Each case below runs the same `assert(checkSig(sigA, pubA) ||
 * checkSig(sigB, pubB))` probe through two engines:
 *
 *   - `ScriptExecutionContract.executeSigned` — the compiled script on
 *     `@bsv/sdk` `Spend.validate()` (version-1 consensus rule set), with sigB
 *     replaced by a real signature over the real sighash, so the B-arm is
 *     genuinely satisfiable and any failure is the A-arm's doing. This is the
 *     oracle.
 *   - `TestContract` — the interpreter, with sigB a valid signature over the
 *     interpreter's fixed TEST_MESSAGE.
 *
 * The A-arm carries, in turn: a DER signature with a corrupted SEQUENCE
 * length, a high-S signature, a well-formed public key with an unknown prefix,
 * and three controls that must NOT abort — a well-formed signature by the
 * wrong key (Spend has no NULLFAIL: it pushes false), an empty signature
 * (pushes false), and an uncompressed public key.
 *
 * What this proves: for each of those A-arm encodings the interpreter now
 * reaches the oracle's verdict — abort for the three malformed encodings,
 * fall through to the B-arm for the three controls — so the `||` shape no
 * longer turns an on-chain abort into an off-chain success.
 *
 * What this does not prove: (a) the interpreter still accepts a bare DER
 * signature with no trailing sighash-type byte (the shape `signTestMessage`
 * returns, documented and relied on), which Spend aborts on — the interpreter
 * signs a fixed test message, not a sighash, so it cannot model the
 * sighash-type byte; (b) the true-path agreement for a signature that verifies
 * in BOTH engines — the interpreter's sigB is over TEST_MESSAGE and never
 * verifies on chain, the oracle's sigB is over the real sighash; (c) anything
 * about the SDK ANF interpreters' on-chain mode in any tier, or about
 * CL-BUG-098/099 (Merkle / BLAKE3), which are separate items.
 *
 * N-198 (NULLFAIL, user decision R73.2): a NON-EMPTY, well-formed signature
 * that does not verify aborts the script on a BSV node (BIP146; ARC answers
 * 461), so the interpreter now aborts there too, and the arm that must fail
 * takes an empty signature (`EMPTY_SIG`, issue #106). The two wrong-key cases
 * are therefore `nullfail` cases: `Spend` has NO NULLFAIL rule and pushes
 * false, so for them `Spend` is NOT the oracle — the consensus rule as a node
 * enforces it is (witnessed on regtest by
 * integration/ts/nullfail-multimethod.test.ts). The oracle test still runs
 * them and pins that `Spend` falls through to sigB, documenting the
 * divergence; nothing in this file checks the NULLFAIL verdict against an
 * engine independent of the interpreter.
 */
import { describe, it, expect } from 'vitest';
import { PrivateKey, Signature, BigNumber } from '@bsv/sdk';
import { TestContract } from '../test-contract.js';
import { ScriptExecutionContract } from '../script-execution.js';
import { signTestMessage, pubKeyFromPrivKey } from '../crypto/ecdsa.js';

const SOURCE = `import { SmartContract, assert, checkSig, Sig, PubKey } from 'runar-lang';

export class F227OrProbe extends SmartContract {
  constructor() {
    super();
  }

  public unlock(sigA: Sig, pubA: PubKey, sigB: Sig, pubB: PubKey) {
    assert(checkSig(sigA, pubA) || checkSig(sigB, pubB));
  }
}
`;
const FILE = 'F227OrProbe.runar.ts';

const PRIV_A = '0000000000000000000000000000000000000000000000000000000000000011';
const PRIV_B = '0000000000000000000000000000000000000000000000000000000000000022';
const PRIV_OTHER = '0000000000000000000000000000000000000000000000000000000000000033';
const PUB_A = pubKeyFromPrivKey(PRIV_A);
const PUB_B = pubKeyFromPrivKey(PRIV_B);
const SIGHASH_ALL_FORKID = '41';
const SECP256K1_N = new BigNumber(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
  16,
);

/** A's signature over TEST_MESSAGE, with the SEQUENCE length byte bumped by one. */
function badLengthSig(): string {
  const der = signTestMessage(PRIV_A);
  const len = parseInt(der.slice(2, 4), 16);
  return der.slice(0, 2) + (len + 1).toString(16).padStart(2, '0') + der.slice(4) + SIGHASH_ALL_FORKID;
}

/** A's (valid, verifying) signature over TEST_MESSAGE with s replaced by n - s. */
function highSSig(): string {
  const sig = Signature.fromDER(signTestMessage(PRIV_A), 'hex');
  const high = new Signature(sig.r, SECP256K1_N.sub(sig.s));
  return (high.toDER('hex') as string) + SIGHASH_ALL_FORKID;
}

/** A well-formed, low-S signature by a key that is not pubA. */
function wrongKeySig(): string {
  return signTestMessage(PRIV_OTHER) + SIGHASH_ALL_FORKID;
}

/** PUB_A with its 0x02/0x03 prefix replaced by 0x05: 33 bytes, unknown format. */
const PUB_A_BAD_PREFIX = '05' + PUB_A.slice(2);
const PUB_A_UNCOMPRESSED = PrivateKey.fromHex(PRIV_A).toPublicKey().encode(false, 'hex') as string;

interface Case {
  name: string;
  sigA: string;
  pubA: string;
  /** Oracle verdict: does OP_CHECKSIG on the A-arm abort the script? */
  aborts: boolean;
  /** N-198: aborts on a node under NULLFAIL; `Spend` (no NULLFAIL) does not. */
  nullfail?: boolean;
  /** The Spend error the abort must carry. */
  oracleError?: RegExp;
  /** The interpreter's abort reason (the gate that fired). */
  interpError?: RegExp;
}

const CASES: Case[] = [
  { name: 'DER with a corrupted SEQUENCE length', sigA: badLengthSig(), pubA: PUB_A, aborts: true, oracleError: /signature format is invalid/i, interpError: /not strict DER/ },
  // Spend raises 'must have a low S value' inside the try block of
  // checkSignatureEncoding, whose catch re-raises it as the generic format
  // error — so that is the message the abort carries.
  { name: 'high-S signature', sigA: highSSig(), pubA: PUB_A, aborts: true, oracleError: /signature format is invalid/i, interpError: /low S/ },
  { name: 'public key with an unknown prefix (empty sig)', sigA: '', pubA: PUB_A_BAD_PREFIX, aborts: true, oracleError: /public key/i, interpError: /public key is not a 33-byte/ },
  { name: 'NULLFAIL: well-formed signature by the wrong key', sigA: wrongKeySig(), pubA: PUB_A, aborts: true, nullfail: true, interpError: /non-empty and does not verify \(NULLFAIL\)/ },
  { name: 'control: empty signature', sigA: '', pubA: PUB_A, aborts: false },
  { name: 'NULLFAIL: uncompressed public key, wrong-key signature', sigA: wrongKeySig(), pubA: PUB_A_UNCOMPRESSED, aborts: true, nullfail: true, interpError: /non-empty and does not verify \(NULLFAIL\)/ },
  { name: 'control: empty signature, uncompressed public key', sigA: '', pubA: PUB_A_UNCOMPRESSED, aborts: false },
  // Verifies over TEST_MESSAGE, so the interpreter takes the A-arm. On Spend
  // it is a non-empty signature over the wrong digest, which (no NULLFAIL)
  // falls through to sigB.
  { name: 'control: sigA verifies in the interpreter', sigA: signTestMessage(PRIV_A) + SIGHASH_ALL_FORKID, pubA: PUB_A, aborts: false },
];

describe('F-227: checkSig on a malformed encoding aborts, it does not answer false', () => {
  const script = ScriptExecutionContract.fromSource(SOURCE, {}, FILE);

  for (const c of CASES) {
    // A `nullfail` case is Spend's verdict, not a node's (see header).
    const spendAborts = c.aborts && !c.nullfail;
    it(`oracle (Spend.validate): ${c.name} → ${spendAborts ? 'abort' : 'falls through to sigB'}`, () => {
      const r = script.executeSigned('unlock', [c.sigA, c.pubA, '', PUB_B], 2, PrivateKey.fromHex(PRIV_B));
      if (spendAborts) {
        expect(r.success).toBe(false);
        expect(r.error).toMatch(c.oracleError!);
      } else {
        expect(r).toEqual({ success: true });
      }
    });

    it(`interpreter (TestContract): ${c.name} → ${c.aborts ? 'abort' : 'succeeds'}`, () => {
      const contract = TestContract.fromSource(SOURCE, {}, FILE);
      const r = contract.call('unlock', {
        sigA: c.sigA,
        pubA: c.pubA,
        sigB: signTestMessage(PRIV_B),
        pubB: PUB_B,
      });
      if (c.aborts) {
        expect(r.success).toBe(false);
        expect(r.error).toMatch(/OP_CHECKSIG aborts/);
        expect(r.error).toMatch(c.interpError!);
      } else {
        expect(r.success).toBe(true);
      }
    });
  }
});
