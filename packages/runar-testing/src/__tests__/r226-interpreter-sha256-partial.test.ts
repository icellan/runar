/**
 * R-226 (GK-GAP-003): the ANF interpreter has no `sha256Compress` or
 * `sha256Finalize`, so `TestContract` cannot execute the two contracts that use
 * them — `examples/ts/sha256-compress` and `examples/ts/sha256-finalize`, which
 * also ship as conformance fixtures.
 *
 * Both examples work around it by using `ScriptExecutionContract` (the ScriptVM)
 * instead, so nothing is untested. What is missing is the interpreter half of
 * the differential oracle: the whole point of having two engines is that they
 * disagree when one is wrong, and for these two builtins there is only one
 * engine. A miscompile of the partial-SHA-256 codegen would have nothing to
 * disagree with it.
 *
 * The finding offers "implement both builtins in the interpreter or document
 * that those fixtures are ScriptVM-only". They are pure functions over bytes
 * with a reference implementation already in this repo
 * (`packages/runar-py/runar/builtins.py`), so implementing is both cheap and the
 * option that restores the oracle.
 *
 * The vectors here are FIPS 180-4's: the padded one-block "abc" message against
 * the SHA-256 IV must produce the published digest. They are the same constants
 * the example's ScriptVM test uses, which is what makes this a cross-ENGINE
 * check rather than two copies of one engine's opinion.
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { TestContract } from '../index.js';

const SHA256_INIT = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const ABC_PADDED_BLOCK =
  '6162638000000000000000000000000000000000000000000000000000000000' +
  '0000000000000000000000000000000000000000000000000000000000000018';

const COMPRESS_SRC = `
import { SmartContract, assert, sha256Compress } from 'runar-lang';

class CompressProbe extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(state: ByteString, block: ByteString) {
    assert(sha256Compress(state, block) === this.expected);
  }
}
`;

const FINALIZE_SRC = `
import { SmartContract, assert, sha256Finalize } from 'runar-lang';

class FinalizeProbe extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(state: ByteString, remaining: ByteString, msgBitLen: bigint) {
    assert(sha256Finalize(state, remaining, msgBitLen) === this.expected);
  }
}
`;

/** Run one spend and return the interpreter's verdict. */
function spend(
  src: string,
  fileName: string,
  expected: string,
  args: Record<string, unknown>,
): { success: boolean; error?: string } {
  const c = TestContract.fromSource(src, { expected }, fileName);
  const result = c.call('verify', args);
  return { success: result.success, error: result.error };
}

describe('R-226: the interpreter executes the partial-SHA-256 builtins', () => {
  it('sha256Compress(IV, padded "abc") is the FIPS 180-4 digest', () => {
    const r = spend(COMPRESS_SRC, 'CompressProbe.runar.ts', SHA256_ABC, {
      state: SHA256_INIT,
      block: ABC_PADDED_BLOCK,
    });
    expect(r.error ?? '').not.toMatch(/Unknown function/);
    expect(r.success, r.error).toBe(true);
  });

  it('a wrong expected digest still fails the assert', () => {
    // Without this, an implementation that ignored its arguments — or an
    // interpreter that never reached the builtin — would pass the case above.
    const r = spend(COMPRESS_SRC, 'CompressProbe.runar.ts', 'ff'.repeat(32), {
      state: SHA256_INIT,
      block: ABC_PADDED_BLOCK,
    });
    expect(r.success).toBe(false);
  });

  it('sha256Finalize(IV, "abc", 24) is the same digest — the one-block path', () => {
    const r = spend(FINALIZE_SRC, 'FinalizeProbe.runar.ts', SHA256_ABC, {
      state: SHA256_INIT,
      remaining: '616263',
      msgBitLen: 24n,
    });
    expect(r.error ?? '').not.toMatch(/Unknown function/);
    expect(r.success, r.error).toBe(true);
  });

  it('sha256Finalize takes the two-block path for a 56-byte remainder', () => {
    // 56 bytes leaves no room for the 0x80 + 8-byte length in the same block,
    // so the implementation must compress TWICE. The expected digest is
    // computed here with node's own SHA-256 rather than hardcoded, so this
    // checks the builtin against a second implementation.
    const msg = 'a'.repeat(56);
    const digest = createHash('sha256').update(msg).digest('hex');
    const r = spend(FINALIZE_SRC, 'FinalizeProbe.runar.ts', digest, {
      state: SHA256_INIT,
      remaining: Buffer.from(msg).toString('hex'),
      msgBitLen: BigInt(msg.length * 8),
    });
    expect(r.error ?? '').not.toMatch(/Unknown function/);
    expect(r.success, r.error).toBe(true);
  });

  it('the one-block path agrees with node for a short message too', () => {
    const msg = 'runar';
    const digest = createHash('sha256').update(msg).digest('hex');
    const r = spend(FINALIZE_SRC, 'FinalizeProbe.runar.ts', digest, {
      state: SHA256_INIT,
      remaining: Buffer.from(msg).toString('hex'),
      msgBitLen: BigInt(msg.length * 8),
    });
    expect(r.success, r.error).toBe(true);
  });
});
