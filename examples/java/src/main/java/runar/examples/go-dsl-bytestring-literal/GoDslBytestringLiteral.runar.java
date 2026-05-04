package runar.examples.godslbytestringliteral;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;

/**
 * GoDslBytestringLiteral -- mirrors
 * {@code examples/go/go-dsl-bytestring-literal/GoDslBytestringLiteral.runar.go}.
 *
 * <p>The Go-DSL fixture exercises Go-only surface features
 * ({@code runar.BigintBig} property type, {@code runar.ByteString("\\x00\\x6a")}
 * literal). In Java the equivalent surface is plain {@link Bigint} /
 * {@link ByteString} plus {@code ByteString.fromHex("006a")}. Both lower to the
 * same primitives in the AST.
 */
class GoDslBytestringLiteral extends SmartContract {

    @Readonly Bigint target;
    @Readonly ByteString expected;

    GoDslBytestringLiteral(Bigint target, ByteString expected) {
        super(target, expected);
        this.target = target;
        this.expected = expected;
    }

    @Public
    void check(Bigint a, Bigint b) {
        assertThat(a.plus(b).equals(target));
        assertThat(ByteString.fromHex("006a").equals(expected));
    }
}
