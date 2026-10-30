package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * F-189 (CL-BUG-244) — boundary integer literals on {@code .runar.java} compile to the
 * TypeScript reference's bytes.
 *
 * <p>The reviewed claim, that {@code 0xFFFFFFFF} must read as 4294967295, is not what the
 * reference does: user decision R15 (F-026) gives every surface its host language's value,
 * and javac reads an unsuffixed {@code 0xFFFFFFFF} as the {@code int} -1. The TS reference
 * ({@code int-literal.ts parseJava}), {@code int-literal-cases.json} and all seven tiers agree
 * on -1; {@code 0xFFFFFFFFL} is the Java spelling of 4294967295. Those rows are pinned below
 * as they are.
 *
 * <p>The divergence the 7-tier probe did find is the minus sign. javac's parser folds a minus
 * in front of a decimal literal into the literal itself ({@code -5} becomes one literal of
 * value -5). This tier passed that value straight through, so {@code -5} compiled to a single
 * push of -5, while the TS reference (and the five other tiers) parse it as negation applied
 * to 5 and emit different bytes, in both fold modes.
 *
 * <p>What this proves: for each literal, through both the {@code Bigint.of(lit)} path and the
 * bare-literal path, this tier's hex equals the hex the TS reference CLI emits for the same
 * {@code .runar.java} source (pinned from the TS tier's {@code runar-cli compile --hex} on 2026-10-05), with folding
 * ON and OFF. What it does NOT prove: the other tiers (the CLI probe in the F-189 report
 * covers them), or that the two spellings behave the same on chain.
 */
class F189JavaLiteralSignTest {

    private static String src(String arg) {
        return "package t;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\n"
            + "import runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\n"
            + "import static runar.lang.Builtins.assertThat;\n\nclass T extends SmartContract {\n\n"
            + "    @Readonly Bigint target;\n\n    T(Bigint target) {\n        super(target);\n"
            + "        this.target = target;\n    }\n\n    @Public\n    void verify(Bigint a) {\n"
            + "        assertThat(a.gt(" + arg + "));\n    }\n}\n";
    }

    /** literal, TS reference hex fold-ON, TS reference hex fold-OFF. */
    private static final String[][] CASES = {
        // R15: host (javac) values, unchanged by this item.
        {"0xFFFFFFFF", "4fa0", "4fa0"},
        {"0xFFFFFFFFL", "05ffffffff00a0", "05ffffffff00a0"},
        {"0x80000000", "050000008080a0", "050000008080a0"},
        {"2147483648L", "050000008000a0", "050000008000a0"},
        {"0x7FFFFFFFFFFFFFFFL", "08ffffffffffffff7fa0", "08ffffffffffffff7fa0"},
        {"0xFFFFFFFFFFFFFFFFL", "4fa0", "4fa0"},
        {"037777777777", "4fa0", "4fa0"},
        {"0", "00a0", "00a0"},
        // A minus in front of a literal is negation of that literal.
        {"-1", "4fa0", "518fa0"},
        {"-5", "0185a0", "558fa0"},
        {"- 5", "0185a0", "558fa0"},
        {"-2147483647", "04ffffffffa0", "04ffffff7f8fa0"},
        {"-2147483648", "050000008080a0", "0500000080008fa0"},
        {"-9223372036854775808L", "09000000000000008080a0", "090000000000000080008fa0"},
        {"-0x80000000", "050000008000a0", "0500000080808fa0"},
        {"-(5)", "0185a0", "558fa0"},
    };

    @Test
    void boundaryLiteralsMatchTheTsReference() throws Exception {
        List<String> bad = new ArrayList<>();
        for (String[] c : CASES) {
            for (String arg : new String[] {"Bigint.of(" + c[0] + ")", c[0]}) {
                String on = PipelineTestSupport.hex(src(arg), "T.runar.java", false);
                String off = PipelineTestSupport.hex(src(arg), "T.runar.java", true);
                if (!on.equals(c[1])) bad.add(arg + " fold-ON: want " + c[1] + ", got " + on);
                if (!off.equals(c[2])) bad.add(arg + " fold-OFF: want " + c[2] + ", got " + off);
            }
        }
        assertTrue(bad.isEmpty(), String.join("\n", bad));
    }
}
