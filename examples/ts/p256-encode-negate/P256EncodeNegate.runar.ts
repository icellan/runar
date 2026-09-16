import { SmartContract, assert, p256Negate, p256EncodeCompressed } from 'runar-lang';
import type { P256Point, ByteString } from 'runar-lang';

/**
 * P256EncodeNegate — executed coverage for p256Negate and p256EncodeCompressed.
 *
 * Both builtins were among the 30 of runar-lang's 105 `export function`s that
 * appeared in ZERO fixtures' `expected-ir.json` and that the fuzzer cannot
 * generate. `p256-primitives` exercises Add / Mul / MulGen / OnCurve and stops
 * there, so seven compilers shipped negate and compress with no cross-tier
 * byte comparison and nothing that ever ran them.
 *
 * The compression half is not a minor omission. CL-BUG-095 was exactly here:
 * the parity byte used to be read from the blob's LAST byte rather than a
 * fixed offset, so appending one byte FLIPPED THE SIGN of the compressed
 * encoding — the same point compressed to 02‖x or 03‖x at the caller's
 * choice, and anything that hashes a compressed pubkey became forgeable
 * between the two spellings. The fix (verify the width, read parity from
 * offset 31 of y) had no fixture standing on it until this one.
 *
 * `conformance/p256_encode_negate_execution_test.go` spends this fixture's
 * real locking script against a P-256 implementation written independently in
 * Go, at the boundaries that matter:
 *
 *   negate      G and a derived point; the involution negate(negate(P)) == P;
 *               y == 0, where p - y must reduce back to 0 and not to p;
 *               a non-canonical coordinate (x == p, y == p), which the
 *               canonicity guard must refuse;
 *               a 65-byte and a 63-byte blob, which the width gate must refuse
 *   compress    the 02/03 prefix in BOTH parities, so a flipped parity bit
 *               cannot pass; the CL-BUG-095 shape itself — the same point
 *               with one byte appended, which must be REFUSED rather than
 *               compressed to the opposite prefix
 *
 * Measured, both builtins are correct at every one of those. The value here is
 * the gate, not a fix.
 */
class P256EncodeNegate extends SmartContract {
  readonly expectedCompressed: ByteString;

  constructor(expectedCompressed: ByteString) {
    super(expectedCompressed);
    this.expectedCompressed = expectedCompressed;
  }

  /** (x, y) -> (x, p - y). Guards coordinate canonicity AND the 64-byte width. */
  public checkNegate(p: P256Point, expected: P256Point): void {
    const n: P256Point = p256Negate(p);
    assert(n == expected);
  }

  /** Point -> 33-byte 02/03‖x. Guards the width; parity is read at a fixed offset. */
  public checkEncode(p: P256Point, expected: ByteString): void {
    const e: ByteString = p256EncodeCompressed(p);
    assert(e == expected);
  }

  /** Composed: compressing the negation must flip the prefix and nothing else. */
  public checkNegateThenEncode(p: P256Point): void {
    const n: P256Point = p256Negate(p);
    const e: ByteString = p256EncodeCompressed(n);
    assert(e == this.expectedCompressed);
  }
}
