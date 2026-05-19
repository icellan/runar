package runar.compiler.ir.anf;

/**
 * <b>TEST-ONLY synthetic {@link AnfValue} variant.</b>
 *
 * <p>This class exists solely so {@code UnknownAnfKindTest} can construct
 * an {@link AnfValue} whose runtime {@code kind()} is not in the schema
 * and drive it through every dispatcher to verify that each one rejects
 * unknown kinds with a {@link runar.compiler.ir.UnknownAnfKindError}
 * instead of silently falling through.
 *
 * <p>The class is package-private and intentionally absent from every
 * production dispatch site — no compiler pass should ever handle it.
 * If you find yourself wanting to use it from anywhere outside the
 * regression test, you are doing something wrong.
 *
 * <p>Mirrors the TypeScript pattern {@code { kind: 'synthetic...' } as
 * unknown as ANFValue} from
 * {@code packages/runar-compiler/src/__tests__/unknown-anf-kind.test.ts}.
 */
public record SyntheticAnfValueForTests(String kind) implements AnfValue {
    public static AnfValue of(String kind) {
        return new SyntheticAnfValueForTests(kind);
    }
}
