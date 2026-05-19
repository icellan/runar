package runar.compiler.ir.anf;

/**
 * The right-hand side of a single ANF {@code let}-binding. Sealed over
 * the full set of value kinds from
 * {@code packages/runar-ir-schema/src/anf-ir.ts}.
 */
public sealed interface AnfValue
    permits LoadParam, LoadProp, LoadConst, BinOp, UnaryOp, Call, MethodCall,
            If, Loop, Assert, UpdateProp, GetStateScript, CheckPreimage,
            DeserializeState, AddOutput, AddRawOutput, AddDataOutput,
            ArrayLiteral, RawScript,
            // Test-only stub used by UnknownAnfKindTest to drive every
            // dispatcher with a kind that is not in the production schema.
            // No production dispatch site handles this variant — that is
            // the whole point of the F-003 regression guard.
            SyntheticAnfValueForTests {
    String kind();
}
