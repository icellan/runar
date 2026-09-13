package runar.compiler.passes;

import runar.compiler.ir.ast.SourceLocation;

/**
 * Where a lowering pass currently is, for the error path only (R-144).
 *
 * <p>Passes 4 and 5 refuse a construct they must not emit by throwing, across
 * 62 sites (10 in {@link AnfLower}, 52 in {@link StackLower}). Threading a
 * {@code SourceLocation} into every throw would be 62 edits and would miss the
 * 63rd. Instead each pass PUBLISHES where it is at the choke point that already
 * holds the answer — {@code AnfLower.lowerStatement}, which already tracks
 * {@code currentSourceLoc} for the bindings it emits, and
 * {@code StackLower.lowerBinding}, which has the {@code AnfBinding} and
 * therefore its {@code sourceLoc} — and {@link runar.compiler.Cli} reads it when
 * a pass throws.
 *
 * <p>This is the Java peer of {@code compilers/rust/src/refusal.rs} (R-138),
 * and it formats exactly like {@code Validate.Ctx.formatAt}, so a pass-4 or
 * pass-5 refusal is indistinguishable in shape from a validator diagnostic.
 *
 * <p>The holder is a {@link ThreadLocal}: the compiler drives these passes from
 * one thread, and the daemon serves one compile per thread, so a published
 * location can never be read by an unrelated compile. It is cleared on entry to
 * each pass, so a stale position from an earlier compile cannot be attached to a
 * later refusal.
 */
public final class PassLocation {

    private static final ThreadLocal<SourceLocation> CURRENT = new ThreadLocal<>();

    private PassLocation() {}

    /**
     * Publish the position the pass is working at. Cheap enough to call per
     * statement / per binding: one {@code ThreadLocal} write.
     */
    public static void set(SourceLocation loc) {
        CURRENT.set(loc);
    }

    /** Drop any published position. Called on entry to each pass. */
    public static void clear() {
        CURRENT.remove();
    }

    /** Read and drop the published position. Null when the pass published none. */
    public static SourceLocation take() {
        SourceLocation loc = CURRENT.get();
        CURRENT.remove();
        return loc;
    }

    /**
     * {@code file:line:column: msg}, degrading to {@code file: msg} and then to
     * the bare message — byte-identical to {@code Validate.Ctx.formatAt}, so
     * every tool that already parses a Java-tier diagnostic parses these too.
     */
    public static String formatAt(String msg, SourceLocation loc) {
        if (loc == null) {
            return msg;
        }
        if (loc.file() != null && !loc.file().isEmpty() && loc.line() > 0) {
            return loc.file() + ":" + loc.line() + ":" + loc.column() + ": " + msg;
        }
        if (loc.file() != null && !loc.file().isEmpty()) {
            return loc.file() + ": " + msg;
        }
        return msg;
    }
}
