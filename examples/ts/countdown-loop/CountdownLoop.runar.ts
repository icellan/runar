import { SmartContract, assert } from 'runar-lang';

/**
 * CountdownLoop — the `step = -1` half of the loop shape (R-102).
 *
 * `loop-shapes` closed the non-zero-START half and said so explicitly: "The
 * descending half is still open: no fixture anywhere carries `step = -1`, and
 * three of the nine surfaces cannot spell a decrementing loop at all (N-130)."
 * That was accurate. Countdown lowering shipped in all seven tiers and
 * cross-tier parity had never once been measured on it.
 *
 * What the gap was hiding, found by closing it:
 *
 *   - The Move frontend's `while`-fold matched `i = i + …` only, so
 *     `i = i - 1` fell through to a synthetic stub whose trip count came out
 *     ZERO. Six tiers compiled the loop body — every assertion in it — clean
 *     out of the locking script, exit 0, no diagnostic.
 *   - The `.runar.zig` surface never set `descending` from its comparison in
 *     the Zig tier, so `while (i > 1) : (i -= 1)` unrolled zero times THERE
 *     while the other six lowered a real countdown from the same bytes.
 *   - `range(a, b, -1)`, `n.downto(m)` and `(a..b).rev()` did not parse at
 *     all: three of the nine surfaces could not spell a countdown, which is
 *     why no such fixture could exist.
 *
 * The loop descends:
 *
 *   loop 1 (i = 5n; i > 1n; i--):  5 + 4 + 3 + 2 = 14
 *
 * so `verify(seed)` asserts `seed + 14`.
 *
 * Two facts make that arithmetic worth asserting rather than just the trip
 * count: 14 is not 4 times anything, so a dropped body, a wrong start and an
 * ascending iterator each produce a different wrong sum; and the equivalent
 * ASCENDING loop of the same length (0, 1, 2, 3) sums to 6 — a number this
 * fixture must never accept.
 */
export class CountdownLoop extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(seed: bigint) {
    let acc: bigint = seed;
    for (let i = 5n; i > 1n; i--) {
      acc = acc + i;
    }
    assert(acc === this.target);
  }
}
