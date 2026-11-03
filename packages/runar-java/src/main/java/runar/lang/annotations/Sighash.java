package runar.lang.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares the BIP-143 sighash mode a {@link Public} method's covenant (and
 * the preimage the SDK builds for it) commits to — the native Java spelling of
 * the {@code @sighash} directive (N-093; {@code .runar.ts} spells it as a
 * {@code /** @sighash FLAGS *&#47;} comment).
 *
 * <p>{@link #value()} is a {@code |}-separated flag list from {@code ALL},
 * {@code NONE}, {@code SINGLE}, {@code FORKID}, {@code ANYONECANPAY}: exactly
 * one base type ({@code ALL}/{@code NONE}/{@code SINGLE}), {@code FORKID}
 * mandatory, e.g. {@code @Sighash("SINGLE|FORKID")}. Without the annotation a
 * public method commits to {@code ALL|FORKID}. The compiler refuses it on a
 * non-public method, on the constructor and on a field, and refuses a
 * malformed flag list, rather than falling back to the default.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface Sighash {
    /** The flag list, e.g. {@code "SINGLE|FORKID"}. */
    String value();
}
