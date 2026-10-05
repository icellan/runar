import { SmartContract, assert, ecAdd, ecMulGen } from 'runar-lang';
import type { Point } from 'runar-lang';

/**
 * EcChainedRewrite -- two EC optimizer rules firing on ONE binding (F-115).
 *
 * `ecAdd(ecMulGen(n - 7), ecMulGen(7))` first meets ec-mulgen-add (Rule 10),
 * which fuses it to `ecMulGen((n - 7 + 7) mod n)` = `ecMulGen(0)`. That
 * rewritten value is itself ec-mulgen-zero (Rule 5), so a fixed-point optimizer
 * folds `r` to the point at infinity: the 64 zero bytes. The TS tier made a
 * single pass and stopped at `ecMulGen(0)`, emitting a runtime scalar
 * multiplication the other six tiers do not -- a cross-tier hex divergence.
 *
 * The scalar is n - 7 written out in decimal (115792...494330) because the
 * Go/Rust/Move/Zig/Java surfaces read `0x...` as a ByteString, and a constant
 * expression like `n - 7` only folds to a literal with constant folding ON.
 * The two inner `ecMulGen` calls stay in the script (calls are never
 * dead-code eliminated), so the deployed script is ~851 KB.
 */
class EcChainedRewrite extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: Point) {
    const r = ecAdd(ecMulGen(115792089237316195423570985008687907852837564279074904382605163141518161494330n), ecMulGen(7n));
    assert(r === p);
  }
}
