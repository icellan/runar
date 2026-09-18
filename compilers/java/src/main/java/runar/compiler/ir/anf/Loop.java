package runar.compiler.ir.anf;

import java.math.BigInteger;
import java.util.List;

/**
 * Bounded, compile-time-unrolled loop.
 *
 * <p>The loop is unrolled {@code count} times; on iteration {@code i}
 * (0-based) the iterator variable holds {@code start + i * step}
 * (issue #121). Zero-start counting-up loops carry {@code start = 0}
 * and {@code step = 1}, which reproduces the historical
 * {@code i = 0..count-1} lowering byte-for-byte. Countdown loops carry
 * {@code step = -1}.
 */
public record Loop(int count, List<AnfBinding> body, String iterVar, BigInteger start, int step)
    implements AnfValue {

    /**
     * Maximum number of iterations a single loop binding may unroll to.
     *
     * <p>The bound already existed on the {@code --ir} input path in the Go,
     * Python and Ruby tiers but nothing applied it to a loop written in source,
     * in any tier. A source contract could therefore ask for an unroll count no
     * machine can honour, and each tier failed differently — a silently dropped
     * loop body in Go and Rust, a hang in TypeScript, Python and Ruby, a panic
     * in Zig, and here an {@code ArithmeticException} whose message named
     * neither the loop nor the limit. CL-BUG-088.
     */
    public static final int MAX_LOOP_COUNT = 10_000;

    @Override
    public String kind() {
        return "loop";
    }
}
