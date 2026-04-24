package runar.lang.sdk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Compiled Rúnar contract artifact. Java mirror of the TS
 * {@code RunarArtifact} interface and Go {@code RunarArtifact} struct.
 *
 * <p>Only the fields the deployment SDK consumes are modelled. The
 * optional {@code sourceMap}, IR snapshots, and Groth16-WA metadata
 * are ignored on load.
 */
public record RunarArtifact(
    String version,
    String compilerVersion,
    String contractName,
    ABI abi,
    String scriptHex,
    String asm,
    String buildTimestamp,
    List<StateField> stateFields,
    List<ConstructorSlot> constructorSlots,
    List<CodeSepIndexSlot> codeSepIndexSlots,
    Integer codeSeparatorIndex,
    List<Integer> codeSeparatorIndices
) {

    public RunarArtifact {
        stateFields = stateFields == null ? List.of() : Collections.unmodifiableList(stateFields);
        constructorSlots = constructorSlots == null ? List.of() : Collections.unmodifiableList(constructorSlots);
        codeSepIndexSlots = codeSepIndexSlots == null ? List.of() : Collections.unmodifiableList(codeSepIndexSlots);
        codeSeparatorIndices = codeSeparatorIndices == null ? List.of() : Collections.unmodifiableList(codeSeparatorIndices);
    }

    public boolean isStateful() {
        return stateFields != null && !stateFields.isEmpty();
    }

    // ------------------------------------------------------------------
    // JSON loading
    // ------------------------------------------------------------------

    /**
     * Parses a {@code RunarArtifact} from the JSON produced by any of
     * the six compilers. Accepts either a bare artifact object or a
     * wrapper that has an {@code "artifact"} field (as produced by
     * {@code compiler-ts} test fixtures).
     */
    public static RunarArtifact fromJson(String json) {
        Object tree = Json.parse(json);
        Map<String, Object> root = Json.asObject(tree);
        if (root.containsKey("artifact") && root.get("artifact") instanceof Map) {
            root = Json.asObject(root.get("artifact"));
        }
        return fromMap(root);
    }

    private static RunarArtifact fromMap(Map<String, Object> m) {
        String version = Json.asString(m.get("version"));
        String compilerVersion = Json.asString(m.get("compilerVersion"));
        String contractName = Json.asString(m.get("contractName"));
        ABI abi = ABI.fromMap(Json.asObject(m.get("abi")));
        String scriptHex = Json.asString(m.get("script"));
        String asm = Json.asString(m.get("asm"));
        String buildTimestamp = Json.asString(m.get("buildTimestamp"));

        List<StateField> stateFields = new ArrayList<>();
        if (m.get("stateFields") instanceof List<?> sfl) {
            for (Object o : sfl) stateFields.add(StateField.fromMap(Json.asObject(o)));
        }
        List<ConstructorSlot> cs = new ArrayList<>();
        if (m.get("constructorSlots") instanceof List<?> csl) {
            for (Object o : csl) cs.add(ConstructorSlot.fromMap(Json.asObject(o)));
        }
        List<CodeSepIndexSlot> cssi = new ArrayList<>();
        if (m.get("codeSepIndexSlots") instanceof List<?> csil) {
            for (Object o : csil) cssi.add(CodeSepIndexSlot.fromMap(Json.asObject(o)));
        }
        Integer codeSep = null;
        if (m.containsKey("codeSeparatorIndex") && m.get("codeSeparatorIndex") != null) {
            codeSep = Json.asInt(m.get("codeSeparatorIndex"));
        }
        List<Integer> codeSepIndices = new ArrayList<>();
        if (m.get("codeSeparatorIndices") instanceof List<?> cil) {
            for (Object o : cil) codeSepIndices.add(Json.asInt(o));
        }

        return new RunarArtifact(
            version,
            compilerVersion,
            contractName,
            abi,
            scriptHex,
            asm,
            buildTimestamp,
            stateFields,
            cs,
            cssi,
            codeSep,
            codeSepIndices
        );
    }

    // ------------------------------------------------------------------
    // Nested types
    // ------------------------------------------------------------------

    public record ABI(ABIConstructor constructor, List<ABIMethod> methods) {
        public ABI {
            methods = methods == null ? List.of() : Collections.unmodifiableList(methods);
        }
        static ABI fromMap(Map<String, Object> m) {
            ABIConstructor ctor = ABIConstructor.fromMap(Json.asObject(m.get("constructor")));
            List<ABIMethod> methods = new ArrayList<>();
            if (m.get("methods") instanceof List<?> ml) {
                for (Object o : ml) methods.add(ABIMethod.fromMap(Json.asObject(o)));
            }
            return new ABI(ctor, methods);
        }
    }

    public record ABIConstructor(List<ABIParam> params) {
        public ABIConstructor {
            params = params == null ? List.of() : Collections.unmodifiableList(params);
        }
        static ABIConstructor fromMap(Map<String, Object> m) {
            List<ABIParam> ps = new ArrayList<>();
            if (m.get("params") instanceof List<?> pl) {
                for (Object o : pl) ps.add(ABIParam.fromMap(Json.asObject(o)));
            }
            return new ABIConstructor(ps);
        }
    }

    public record ABIMethod(String name, List<ABIParam> params, boolean isPublic, Boolean isTerminal) {
        public ABIMethod {
            params = params == null ? List.of() : Collections.unmodifiableList(params);
        }
        static ABIMethod fromMap(Map<String, Object> m) {
            String name = Json.asString(m.get("name"));
            List<ABIParam> ps = new ArrayList<>();
            if (m.get("params") instanceof List<?> pl) {
                for (Object o : pl) ps.add(ABIParam.fromMap(Json.asObject(o)));
            }
            boolean isPublic = m.containsKey("isPublic") && Json.asBool(m.get("isPublic"));
            Boolean isTerminal = null;
            if (m.containsKey("isTerminal") && m.get("isTerminal") != null) {
                isTerminal = Json.asBool(m.get("isTerminal"));
            }
            return new ABIMethod(name, ps, isPublic, isTerminal);
        }
    }

    public record ABIParam(String name, String type, FixedArrayMeta fixedArray) {
        static ABIParam fromMap(Map<String, Object> m) {
            FixedArrayMeta fa = null;
            if (m.get("fixedArray") instanceof Map) {
                fa = FixedArrayMeta.fromMap(Json.asObject(m.get("fixedArray")));
            }
            return new ABIParam(Json.asString(m.get("name")), Json.asString(m.get("type")), fa);
        }
    }

    public record FixedArrayMeta(String elementType, int length, List<String> syntheticNames) {
        public FixedArrayMeta {
            syntheticNames = syntheticNames == null ? List.of() : Collections.unmodifiableList(syntheticNames);
        }
        static FixedArrayMeta fromMap(Map<String, Object> m) {
            String et = Json.asString(m.get("elementType"));
            int len = Json.asInt(m.get("length"));
            List<String> names = new ArrayList<>();
            if (m.get("syntheticNames") instanceof List<?> nl) {
                for (Object o : nl) names.add(Json.asString(o));
            }
            return new FixedArrayMeta(et, len, names);
        }
    }

    public record StateField(String name, String type, int index, Object initialValue, FixedArrayMeta fixedArray) {
        static StateField fromMap(Map<String, Object> m) {
            FixedArrayMeta fa = null;
            if (m.get("fixedArray") instanceof Map) {
                fa = FixedArrayMeta.fromMap(Json.asObject(m.get("fixedArray")));
            }
            return new StateField(
                Json.asString(m.get("name")),
                Json.asString(m.get("type")),
                Json.asInt(m.get("index")),
                m.get("initialValue"),
                fa
            );
        }
    }

    public record ConstructorSlot(int paramIndex, int byteOffset) {
        static ConstructorSlot fromMap(Map<String, Object> m) {
            return new ConstructorSlot(Json.asInt(m.get("paramIndex")), Json.asInt(m.get("byteOffset")));
        }
    }

    public record CodeSepIndexSlot(int byteOffset, int codeSepIndex) {
        static CodeSepIndexSlot fromMap(Map<String, Object> m) {
            return new CodeSepIndexSlot(Json.asInt(m.get("byteOffset")), Json.asInt(m.get("codeSepIndex")));
        }
    }
}
