package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.AnfProgram;

/**
 * N-113 — the two shapes the Go tier rejected alone (R-079 / R-081).
 *
 * <p>Both are {@code --ir}-only: the source path refuses each shape in
 * {@code Validate.java}, and {@code AnfLoader.parse} is reached only from the
 * {@code --ir} path. Go grew these guards first
 * ({@code compilers/go/ir/loader.go}) and was deliberately, transiently
 * stricter than its six peers until N-113;
 * {@code conformance/negatives/ir-rejection-parity.test.ts} is the gate that
 * now compares the six.
 */
class N113IrTrustBoundaryTest {

    /**
     * A one-method contract parameterised on the two fields under test, so
     * every case below differs from the VALID control in exactly one way.
     */
    private static String ir(boolean isPublic, String rawBytes, int outArity) {
        return """
            {"contractName":"Anyone","properties":[],"methods":[
              {"name":"unlock","params":[],"isPublic":%s,"body":[
                {"name":"t0","value":{"kind":"raw_script","bytes":"%s","in_arity":0,"out_arity":%d}}
              ]}
            ]}
            """.formatted(isPublic, rawBytes, outArity);
    }

    /** The control every case below is derived from. A probe whose control
     *  also fails proves nothing. */
    @Test
    void controlValidIrIsAccepted() {
        AnfProgram p = AnfLoader.parse(ir(true, "51", 1));
        assertEquals("Anyone", p.contractName());
    }

    /**
     * R-079: lowering pops in_arity and pushes out_arity on the stack model
     * while emission writes nothing for a zero-length span. The span degrades
     * to the identity function and a DIFFERENT WITNESS spends the output.
     * Measured on @bsv/sdk's Spend: {@code 8f01859c} accepts x=5 and rejects
     * x=-5; with the body erased, {@code 01859c} does the opposite.
     */
    @Test
    void rejectsEmptyRawScriptBody() {
        RuntimeException ex = assertThrows(
            RuntimeException.class, () -> AnfLoader.parse(ir(true, "", 1)));
        assertTrue(ex.getMessage().contains("empty bytes body"), ex.getMessage());
    }

    /**
     * The degenerate in=0/out=0 case is harmless on its own and is rejected
     * anyway: mirroring the source validator exactly beats a narrower
     * arity-conditional rule that would differ from the rule one pass earlier.
     */
    @Test
    void rejectsEmptyRawScriptBodyEvenAtZeroArity() {
        assertThrows(RuntimeException.class, () -> AnfLoader.parse(ir(true, "", 0)));
    }

    /**
     * R-081: emission succeeds with an EMPTY locking script, which is
     * anyone-can-spend. On @bsv/sdk's Spend under full consensus wrappers,
     * {@code lock=""} with {@code unlock=OP_1 (0x51)} validates.
     */
    @Test
    void rejectsNoPublicMethods() {
        RuntimeException ex = assertThrows(
            RuntimeException.class, () -> AnfLoader.parse(ir(false, "51", 1)));
        assertTrue(ex.getMessage().contains("no public methods"), ex.getMessage());
    }

    @Test
    void rejectsEmptyMethodList() {
        RuntimeException ex = assertThrows(RuntimeException.class, () ->
            AnfLoader.parse("{\"contractName\":\"Empty\",\"properties\":[],\"methods\":[]}"));
        assertTrue(ex.getMessage().contains("no public methods"), ex.getMessage());
    }

    /**
     * Ordering matters and is asserted, not assumed: when a binding is ALSO
     * malformed, the malformed binding is the more actionable diagnostic. Same
     * ordering as {@code compilers/go/ir/loader.go} — methods are decoded
     * before the entry-point check runs.
     */
    @Test
    void structuralErrorsKeepPriorityOverTheEntryPointError() {
        RuntimeException ex = assertThrows(
            RuntimeException.class, () -> AnfLoader.parse(ir(false, "515", 1)));
        assertTrue(ex.getMessage().contains("odd hex length"), ex.getMessage());
    }
}
