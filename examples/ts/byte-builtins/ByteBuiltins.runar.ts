import { SmartContract, assert, sha256, ripemd160, split, int2str, reverseBytes } from 'runar-lang';
import type { ByteString, Sha256, Ripemd160 } from 'runar-lang';

/**
 * ByteBuiltins — executed coverage for five byte-level builtins that no
 * conformance fixture called.
 *
 * Measured before this file landed: of the 105 `export function`s in
 * `packages/runar-lang/src/builtins.ts`, `split`, `int2str`, `reverseBytes`
 * and the `Sha256Hash` spelling of `sha256` appeared in ZERO fixtures'
 * `expected-ir.json`, and the fuzzer could not generate any of them. Seven
 * compilers shipped codegen for all four with nothing on either side of it:
 * no cross-tier byte comparison, and no execution.
 *
 * That is the shape the `pow` bug hid in. `pow` DID have a callsite
 * (`math-demo.exponentiate`) and still returned `base^min(exp,32)` for three
 * review rounds, because the callsite was only ever compiled, never spent past
 * the bound. So a callsite is not the deliverable here; the deliverable is a
 * script that gets SPENT at each builtin's boundaries.
 *
 * Every parameter is an unlock argument rather than a baked constant, so one
 * compiled script covers the whole domain. The boundaries this shape exists to
 * reach are driven from `conformance/byte_builtins_execution_test.go`:
 *
 *   split        index 0, index == len, the empty string, and the
 *                out-of-range indices consensus must abort on
 *   int2str      zero, negative, zero width, and a width too small to hold
 *                the value (OP_NUM2BIN's own failure)
 *   reverseBytes empty, one byte, odd length, and 520 bytes — the maximum BSV
 *                element, which is the last of the 520 unrolled iterations
 *   sha256       spelled `Sha256Hash` in the `.runar.go` surface, the only
 *                surface whose parser resolves that alias
 *   ripemd160    the `.runar.go` surface's ONLY spelling for it is
 *                `runar.Ripemd160`, which the TypeScript and Ruby parsers
 *                lowered to an identity binding — the opcode vanished, and the
 *                baked digest became the spending key. That is why this builtin
 *                had zero fixtures: nothing could call it from the Go surface
 *                without wedging cross-tier parity. The parser bug is fixed;
 *                `checkRipemd` is the end-to-end proof, and it is the reason
 *                this contract bakes a SECOND digest.
 *
 * NOTE on `split`: it is single-valued and binds the RIGHT half, lowering to
 * `OP_SPLIT OP_NIP`. Rúnar has no tuple type and no parser accepts array
 * destructuring, so a pair would be unnameable; `left(data, idx)` is the other
 * side of the same cut. `runar-lang` used to declare
 * `split(): [ByteString, ByteString]`, which disagreed with every typechecker
 * and with this file.
 */
class ByteBuiltins extends SmartContract {
  readonly expectedDigest: Sha256;
  readonly expectedRipemd: Ripemd160;

  constructor(expectedDigest: Sha256, expectedRipemd: Ripemd160) {
    super(expectedDigest, expectedRipemd);
    this.expectedDigest = expectedDigest;
    this.expectedRipemd = expectedRipemd;
  }

  /** OP_SPLIT. Binds the right half of `data` at `idx`. */
  public checkSplit(data: ByteString, idx: bigint, expectedTail: ByteString): void {
    const tail: ByteString = split(data, idx);
    assert(tail == expectedTail);
  }

  /** OP_NUM2BIN. Fixed-width little-endian sign-magnitude encoding. */
  public checkInt2Str(value: bigint, width: bigint, expected: ByteString): void {
    const s: ByteString = int2str(value, width);
    assert(s == expected);
  }

  /** 520 unrolled OP_SPLIT / OP_CAT iterations — one per possible byte. */
  public checkReverse(data: ByteString, expected: ByteString): void {
    const r: ByteString = reverseBytes(data);
    assert(r == expected);
  }

  /** OP_SHA256, against the digest baked into the locking script. */
  public checkSha256(preimage: ByteString): void {
    const h: Sha256 = sha256(preimage);
    assert(h == this.expectedDigest);
  }

  /** OP_RIPEMD160, against the digest baked into the locking script. */
  public checkRipemd(preimage: ByteString): void {
    const h: Ripemd160 = ripemd160(preimage);
    assert(h == this.expectedRipemd);
  }
}
