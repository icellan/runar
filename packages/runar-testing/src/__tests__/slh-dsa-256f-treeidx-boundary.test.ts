/**
 * N-160: SLH-DSA-SHA2-256f must accept honest signatures on BOTH sides of the
 * treeIdx 2^63 boundary, not just one.
 *
 * F-034 fixed two 256f defects, one of which was: the first tree address was
 * built with `8 OP_NUM2BIN`, but 256f's tree index has h - h' = 64 bits, so it
 * is >= 2^63 for about half of all signatures and its minimal script number
 * needs a 9th (sign) byte -- `8 OP_NUM2BIN` aborts. The fix
 * (`9 OP_NUM2BIN 8 OP_SPLIT OP_DROP` when `p.h - hp >= 64`,
 * packages/runar-compiler/src/passes/slh-dsa-codegen.ts) was pinned by
 * conformance/witnesses/real-crypto/post-quantum-slhdsa-256f.json, but that
 * witness carries only a treeIdx >= 2^63 (hi) signature + its 1-bit tamper.
 * The treeIdx < 2^63 (lo) side -- the OTHER branch of the `if` -- had no
 * permanent regression coverage: a change that broke ONLY the lo branch (e.g.
 * reversing the condition, or breaking the plain `8 OP_NUM2BIN` path) could
 * land undetected.
 *
 * Both signatures below are from the SAME third-party implementation and the
 * SAME keypair as the F-034 witness (PyPI slh-dsa 0.2.5, Sha2_1Parameter at
 * the repo's SHA-256-only 256f dimensions) -- never from this repo's compiler
 * or its TS reference signer (packages/runar-testing/src/crypto/slh-dsa.ts).
 * The hi vector is read directly from the existing F-034 witness; the lo
 * vector's full provenance (seeds, parameter object, deterministic signing
 * mode, message selection) is recorded in its own `_doc` field in
 * testdata/slh-dsa-256f-treeidx-lo-vector.json. slh-dsa.ts's
 * `slhVerifyVerbose` is used below only to CROSS-CHECK the pinned treeIdx
 * values against the repo's own Hmsg computation -- it is never used to sign.
 *
 * The hi and lo cases are deliberately separate `it`s (not one combined
 * assertion): a combined test would stop at the first failing `expect`, so a
 * regression confined to one side would hide whether the other side still
 * works -- exactly the ambiguity this item exists to close.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { ScriptExecutionContract } from '../script-execution.js';
import { slhVerifyVerbose, SLH_SHA2_256f } from '../crypto/slh-dsa.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const TOP = 1n << 63n;

/** Strip the repo-wide "0x" witness/vector hex convention. */
function unprefix(hex: string): string {
  return hex.startsWith('0x') ? hex.slice(2) : hex;
}

/** Flip the low bit of the final byte -- must invalidate the signature. */
function tamper(sigHex: string): string {
  const last = parseInt(sigHex.slice(-2), 16) ^ 0x01;
  return sigHex.slice(0, -2) + last.toString(16).padStart(2, '0');
}

// -- hi side: reuse the F-034 witness (treeIdx 0x9cc4feac04b4276d >= 2^63) --
const HI_WITNESS_PATH = join(
  __dirname, '..', '..', '..', '..',
  'conformance', 'witnesses', 'real-crypto', 'post-quantum-slhdsa-256f.json',
);
const hiWitness = JSON.parse(readFileSync(HI_WITNESS_PATH, 'utf8')) as {
  constructorArgs: { pubkey: string };
  spends: { expect: string; args: string[] }[];
};
const hiAccept = hiWitness.spends.find(s => s.expect === 'accept')!;
const pubkeyHex = unprefix(hiWitness.constructorArgs.pubkey);
const hiMsgHex = unprefix(hiAccept.args[0]!);
const hiSigHex = unprefix(hiAccept.args[1]!);

// -- lo side: same keypair + signer, a message chosen for treeIdx < 2^63 --
const LO_VECTOR_PATH = join(__dirname, 'testdata', 'slh-dsa-256f-treeidx-lo-vector.json');
const loVector = JSON.parse(readFileSync(LO_VECTOR_PATH, 'utf8')) as {
  pk: string; msg: string; sig: string; treeIdx: string;
};
const loMsgHex = unprefix(loVector.msg);
const loSigHex = unprefix(loVector.sig);

const SOURCE = `
class W extends SmartContract {
  readonly pubkey: ByteString;
  constructor(pubkey: ByteString) { super(pubkey); this.pubkey = pubkey; }
  public spend(msg: ByteString, sig: ByteString) {
    assert(verifySLHDSA_SHA2_256f(msg, sig, this.pubkey));
  }
}`;

describe('SLH-DSA-SHA2-256f treeIdx boundary (N-160)', () => {
  it('same keypair backs both the hi and lo vectors', () => {
    expect(unprefix(loVector.pk)).toBe(pubkeyHex);
  });

  it('pinned treeIdx values straddle 2^63, confirmed against the repo Hmsg', () => {
    const pkBytes = Uint8Array.from(Buffer.from(pubkeyHex, 'hex'));

    const hiTreeIdx = slhVerifyVerbose(
      SLH_SHA2_256f,
      Uint8Array.from(Buffer.from(hiMsgHex, 'hex')),
      Uint8Array.from(Buffer.from(hiSigHex, 'hex')),
      pkBytes,
    ).treeIdx;
    expect(hiTreeIdx).toBe(BigInt('0x9cc4feac04b4276d'));
    expect(hiTreeIdx >= TOP).toBe(true);

    const loTreeIdx = slhVerifyVerbose(
      SLH_SHA2_256f,
      Uint8Array.from(Buffer.from(loMsgHex, 'hex')),
      Uint8Array.from(Buffer.from(loSigHex, 'hex')),
      pkBytes,
    ).treeIdx;
    expect(loTreeIdx).toBe(BigInt(loVector.treeIdx));
    expect(loTreeIdx < TOP).toBe(true);
  });

  // Compiled-script acceptance on the real @bsv/sdk Spend engine. Minimal test
  // count (two `it`s, one per side of the boundary, each compiling its own
  // ~900 KB script) with generous timeouts given the interpreter cost.
  it('compiled script accepts the hi (treeIdx >= 2^63) signature, rejects its tamper',
    () => {
      const contract = ScriptExecutionContract.fromSource(SOURCE, { pubkey: pubkeyHex });

      const acceptResult = contract.execute('spend', [hiMsgHex, hiSigHex]);
      if (!acceptResult.success) console.log('hi accept failed:', acceptResult.error);
      expect(acceptResult.success).toBe(true);

      const tamperResult = contract.execute('spend', [hiMsgHex, tamper(hiSigHex)]);
      expect(tamperResult.success).toBe(false);
    },
    600000,
  );

  it('compiled script accepts the lo (treeIdx < 2^63) signature, rejects its tamper',
    () => {
      const contract = ScriptExecutionContract.fromSource(SOURCE, { pubkey: pubkeyHex });

      const acceptResult = contract.execute('spend', [loMsgHex, loSigHex]);
      if (!acceptResult.success) console.log('lo accept failed:', acceptResult.error);
      expect(acceptResult.success).toBe(true);

      const tamperResult = contract.execute('spend', [loMsgHex, tamper(loSigHex)]);
      expect(tamperResult.success).toBe(false);
    },
    600000,
  );
});

// What this proves: an honest third-party (PyPI slh-dsa 0.2.5) SLH-DSA-SHA2-256f
// signature on EACH side of the treeIdx 2^63 boundary -- the boundary the
// F-034 `h - hp >= 64` wide-arm fix exists for -- verifies through the
// compiled Bitcoin Script on the strict @bsv/sdk Spend engine, and a 1-bit
// tamper on either side is rejected. Reproduced by hand per the TDD protocol:
// forcing `if (p.h - hp >= 64)` to `if (false && p.h - hp >= 64)` in
// slh-dsa-codegen.ts (unconditional plain `8 OP_NUM2BIN`) makes the hi `it`
// fail with the exact pre-F-034 abort
// ("OP_NUM2BIN requires that the size expressed in the top stack item is
// large enough to hold the value...") while the lo `it` still passes --
// confirming these two `it`s, not just one combined one, are what catch a
// regression confined to either branch of that `if`.
//
// What this does not prove: FIPS 205 conformance for 256f (it uses SHA-256
// throughout; FIPS 205 requires SHA-512 for 256f, #137); every possible
// treeIdx/leafIdx alignment (two signatures, not an exhaustive sweep); or
// anything about the other five SLH-DSA parameter sets, none of which have
// h - h' >= 64 and so never take the wide arm.
