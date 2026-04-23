package runar.compiler.ir.stack;

/**
 * A single stack operation inside a {@link StackMethod}. Sealed over the
 * full set of ops from {@code packages/runar-ir-schema/src/stack-ir.ts}.
 *
 * <p>The {@link #op()} discriminator mirrors the {@code op} field of the
 * TypeScript discriminated union; {@link runar.compiler.canonical.Jcs}
 * emits it as a synthetic {@code "op"} field during canonical JSON
 * serialisation.
 *
 * <p>Stack IR is compiler-local — unlike ANF IR it is NOT part of the
 * conformance boundary, but its JSON shape still follows the same
 * canonical-JSON rules because the same schema is used for fixture
 * files.
 */
public sealed interface StackOp
    permits PushOp, DupOp, SwapOp, RollOp, PickOp, DropOp, OpcodeOp, IfOp,
            NipOp, OverOp, RotOp, TuckOp, PlaceholderOp, PushCodeSepIndexOp {
    String op();
}
