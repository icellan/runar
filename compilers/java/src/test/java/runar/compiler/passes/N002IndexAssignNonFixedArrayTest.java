package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * N-002 (CL-BUG-214, the cross-tier half of F-013): an index assignment is
 * only a write when its root is a FixedArray contract property.
 *
 * <p>ExpandFixedArrays rewrites {@code this.arr[i] = v} only when {@code arr}
 * is a FixedArray property. Every other index target (a ByteString property, a
 * local, a parameter, a member-chained root) survived to ANF lowering, which
 * lowered it as a READ. In this tier that READ then failed at emit ("unknown
 * function __array_access"), so Java was fail-closed by accident, with a
 * diagnostic naming an internal helper -- while TS, Go, Rust and Zig emitted a
 * script that drops the write (remediation-logs/N-002).
 *
 * <p>What this proves: the Java tier refuses every non-FixedArray index-write
 * shape below in the VALIDATOR, with F-013's shared diagnostic and a source
 * location, on the TS surface and on the Java surface; FixedArray index writes
 * (literal, runtime, compound, ++, nested literal) still compile.
 *
 * <p>What it does NOT prove: the other tiers (their own suites and
 * conformance/negatives/N81-N94 cover that), or byte-identity of the
 * FixedArray goldens (the conformance golden + multi-format runs do).
 */
class N002IndexAssignNonFixedArrayTest {

    private static final String NEEDLE =
        "index assignment is only supported on FixedArray contract properties; "
            + "the target here is not a FixedArray property";
    private static final Pattern LOCATED =
        Pattern.compile(":(\\d+):\\d+: " + Pattern.quote(NEEDLE) + "$");

    private static String blob(String body) {
        return "import { StatefulSmartContract, ByteString, assert } from 'runar-lang';\n\n"
            + "class Blob extends StatefulSmartContract {\n  blob: ByteString;\n\n"
            + "  constructor(blob: ByteString) {\n    super(blob);\n    this.blob = blob;\n  }\n\n"
            + "  public poke(i: bigint) {\n    " + body + "\n    assert(true);\n  }\n}\n";
    }

    private static final String TS_LOCAL =
        "import { SmartContract, ByteString, assert } from 'runar-lang';\n\n"
            + "class Loc extends SmartContract {\n  readonly h: ByteString;\n\n"
            + "  constructor(h: ByteString) {\n    super(h);\n    this.h = h;\n  }\n\n"
            + "  public unlock(b: ByteString) {\n    let c: ByteString = b;\n    c[0n] = 7n;\n"
            + "    assert(c == this.h);\n  }\n}\n";

    private static final String TS_PARAM =
        "import { SmartContract, ByteString, assert } from 'runar-lang';\n\n"
            + "class Par extends SmartContract {\n  readonly h: ByteString;\n\n"
            + "  constructor(h: ByteString) {\n    super(h);\n    this.h = h;\n  }\n\n"
            + "  public unlock(b: ByteString) {\n    b[0n] = 7n;\n    assert(b == this.h);\n  }\n}\n";

    private static final String JAVA_PROP =
        "package runar.examples.blob;\n\n"
            + "import runar.lang.StatefulSmartContract;\n"
            + "import runar.lang.annotations.Public;\n"
            + "import runar.lang.types.ByteString;\n\n"
            + "import static runar.lang.Builtins.assertThat;\n\n"
            + "class Blob extends StatefulSmartContract {\n\n    ByteString blob;\n\n"
            + "    Blob(ByteString blob) {\n        super(blob);\n        this.blob = blob;\n    }\n\n"
            + "    @Public\n    void poke() {\n        this.blob[0] = 7;\n        assertThat(true);\n    }\n}\n";

    private static final String JAVA_LOCAL_PARAM =
        "package runar.examples.loc;\n\n"
            + "import runar.lang.SmartContract;\n"
            + "import runar.lang.annotations.Public;\n"
            + "import runar.lang.annotations.Readonly;\n"
            + "import runar.lang.types.ByteString;\n\n"
            + "import static runar.lang.Builtins.assertThat;\n\n"
            + "class Loc extends SmartContract {\n\n    @Readonly ByteString h;\n\n"
            + "    Loc(ByteString h) {\n        super(h);\n        this.h = h;\n    }\n\n"
            + "    @Public\n    void unlock(ByteString b) {\n        ByteString c = b;\n"
            + "        c[0] = 7;\n        b[1] = 7;\n        assertThat(c.equals(this.h));\n    }\n}\n";

    private static final String FIXED_ARRAY_WRITES =
        "import { StatefulSmartContract, FixedArray, assert } from 'runar-lang';\n\n"
            + "class Board extends StatefulSmartContract {\n"
            + "  board: FixedArray<bigint, 3> = [0n, 0n, 0n];\n"
            + "  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];\n\n"
            + "  constructor() {\n    super();\n  }\n\n"
            + "  public set(i: bigint, v: bigint) {\n"
            + "    this.board[i] = v;\n    this.board[0n] = v;\n    this.board[1n] += v;\n"
            + "    this.board[2n]++;\n    this.grid[0n][1n] = v;\n    assert(true);\n  }\n}\n";

    private static void assertRefused(String src, String file, int want) throws Exception {
        List<String> errors = PipelineTestSupport.diagnostics(src, file).errors();
        int located = 0;
        for (String e : errors) {
            Matcher m = LOCATED.matcher(e);
            if (m.find()) {
                assertTrue(Integer.parseInt(m.group(1)) > 0, file + ": no line in " + e);
                located++;
            }
        }
        assertEquals(want, located, file + ": expected " + want + " located N-002 diagnostic(s); got " + errors);
        assertFalse(PipelineTestSupport.compiles(src, file), file + " compiled a script that silently drops the write");
    }

    @Test
    void tsSurfaceShapesAreRefused() throws Exception {
        for (String body : List.of(
            "this.blob[0n] = 7n;",
            "this.blob[i] = 7n;",
            "this.blob[0n] += 7n;",
            "this.blob[0n] -= 7n;",
            "this.blob[0n] *= 7n;",
            "this.blob[0n] /= 7n;",
            "this.blob[0n] %= 7n;",
            "this.blob[0n][1n] = 7n;",
            "this.blob.x[0n] = 7n;")) {
            assertRefused(blob(body), "Blob.runar.ts", 1);
        }
        assertRefused(TS_LOCAL, "Loc.runar.ts", 1);
        assertRefused(TS_PARAM, "Par.runar.ts", 1);
    }

    @Test
    void javaSurfaceIsRefused() throws Exception {
        assertRefused(JAVA_PROP, "Blob.runar.java", 1);
        assertRefused(JAVA_LOCAL_PARAM, "Loc.runar.java", 2);
    }

    @Test
    void fixedArrayIndexWritesStillCompile() throws Exception {
        assertEquals(List.of(), PipelineTestSupport.diagnostics(FIXED_ARRAY_WRITES, "Board.runar.ts").errors());
        assertFalse(PipelineTestSupport.hex(FIXED_ARRAY_WRITES, "Board.runar.ts").isEmpty());
    }
}
