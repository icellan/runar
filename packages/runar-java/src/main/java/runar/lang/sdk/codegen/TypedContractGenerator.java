package runar.lang.sdk.codegen;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarArtifact.ABIMethod;
import runar.lang.sdk.RunarArtifact.ABIParam;
import runar.lang.sdk.RunarArtifact.StateField;

/**
 * Emits a typed Java wrapper class for a compiled {@link RunarArtifact}.
 *
 * <p>Parity target: the TypeScript {@code generateTypescript()} in
 * {@code packages/runar-sdk/src/codegen/gen-typescript.ts} and the Go
 * {@code GenerateGo()} in {@code packages/runar-go/sdk_codegen.go}.
 *
 * <p>The generated class wraps {@link runar.lang.sdk.RunarContract} and exposes
 * typed constructor parameters, a {@code deploy(BigInteger satoshis)} helper,
 * one typed method per public ABI method, and typed {@code state()} accessors
 * per state field on stateful contracts. Sig and SigHashPreimage parameters
 * are elided from the user-facing method signature and auto-computed by the
 * underlying SDK at call time. Stateful (non-terminal) methods return the
 * broadcast txid as {@link String}; terminal methods return {@code void}.
 */
public final class TypedContractGenerator {

    private TypedContractGenerator() {}

    /**
     * Generate typed Java source for the given artifact under the target
     * package name. The returned string is a complete .java source file
     * (header comment, package, imports, class).
     */
    public static String generate(RunarArtifact artifact, String packageName) {
        if (artifact == null) throw new IllegalArgumentException("artifact is null");
        if (packageName == null || packageName.isBlank()) {
            throw new IllegalArgumentException("packageName is null or blank");
        }

        String name = artifact.contractName();
        String className = name + "Wrapper";
        boolean isStateful = artifact.isStateful();
        List<ABIMethod> publicMethods = publicMethods(artifact);

        Imports imports = new Imports();
        imports.add("java.math.BigInteger");
        imports.add("java.util.ArrayList");
        imports.add("java.util.List");
        imports.add("runar.lang.sdk.Provider");
        imports.add("runar.lang.sdk.RunarArtifact");
        imports.add("runar.lang.sdk.RunarContract");
        imports.add("runar.lang.sdk.Signer");

        StringBuilder body = new StringBuilder();
        body.append("public final class ").append(className).append(" {\n");
        body.append("    private final RunarContract inner;\n");
        body.append("    private final Provider provider;\n");
        body.append("    private final Signer signer;\n");
        body.append("\n");

        // ---- Constructor -------------------------------------------------
        List<ABIParam> ctorParams = artifact.abi().constructor().params();
        body.append("    public ").append(className).append("(RunarArtifact artifact");
        for (ABIParam p : ctorParams) {
            body.append(", ").append(javaType(p.type(), imports)).append(' ').append(p.name());
        }
        body.append(", Provider provider, Signer signer) {\n");
        body.append("        List<Object> args = new ArrayList<>();\n");
        for (ABIParam p : ctorParams) {
            body.append("        args.add(").append(toSdkValue(p.name(), p.type())).append(");\n");
        }
        body.append("        this.inner = new RunarContract(artifact, args);\n");
        body.append("        this.provider = provider;\n");
        body.append("        this.signer = signer;\n");
        body.append("    }\n");
        body.append("\n");

        // ---- contract() accessor -----------------------------------------
        body.append("    /** Returns the underlying {@link RunarContract}. */\n");
        body.append("    public RunarContract contract() {\n");
        body.append("        return inner;\n");
        body.append("    }\n");
        body.append("\n");

        // ---- deploy(BigInteger) ------------------------------------------
        body.append("    /** Deploys the contract on-chain. Returns the broadcast txid. */\n");
        body.append("    public String deploy(BigInteger satoshis) {\n");
        body.append("        return inner.deploy(provider, signer, satoshis.longValueExact()).txid();\n");
        body.append("    }\n");

        // ---- Public methods ----------------------------------------------
        for (ABIMethod m : publicMethods) {
            body.append('\n');
            boolean terminal = isTerminal(m, isStateful);
            String returnType = terminal ? "void" : "String";
            List<ClassifiedParam> classified = classify(m.params(), isStateful);

            body.append("    /** ")
                .append(terminal ? "Terminal" : "State-mutating")
                .append(" method: ").append(m.name()).append(". */\n");
            body.append("    public ").append(returnType).append(' ').append(safeMethodName(m.name())).append('(');
            boolean first = true;
            for (ClassifiedParam cp : classified) {
                if (cp.hidden || cp.internal) continue;
                if (!first) body.append(", ");
                first = false;
                body.append(javaType(cp.abiType, imports)).append(' ').append(cp.name);
            }
            body.append(") {\n");
            body.append("        List<Object> callArgs = new ArrayList<>();\n");
            for (ClassifiedParam cp : classified) {
                if (cp.internal) continue;
                if (cp.hidden) {
                    body.append("        callArgs.add(null); // ").append(cp.abiType)
                        .append(" auto-computed by SDK\n");
                } else {
                    body.append("        callArgs.add(").append(toSdkValue(cp.name, cp.abiType)).append(");\n");
                }
            }
            if (terminal) {
                body.append("        inner.call(\"").append(m.name()).append("\", callArgs, null, provider, signer);\n");
            } else {
                body.append("        return inner.call(\"").append(m.name()).append("\", callArgs, null, provider, signer).txid();\n");
            }
            body.append("    }\n");
        }

        // ---- State accessors ---------------------------------------------
        if (isStateful) {
            for (StateField f : artifact.stateFields()) {
                body.append('\n');
                String javaT = javaType(f.type(), imports);
                body.append("    /** Decoded state field {@code ").append(f.name()).append("}. */\n");
                body.append("    public ").append(javaT).append(' ').append(safeMethodName(f.name())).append("() {\n");
                body.append("        return (").append(javaT).append(") inner.state(\"").append(f.name()).append("\");\n");
                body.append("    }\n");
            }
        }

        body.append("}\n");

        // ---- Assemble file ----------------------------------------------
        StringBuilder out = new StringBuilder();
        out.append("// Generated by: runar codegen\n");
        out.append("// Source: ").append(name).append("\n");
        out.append("// Do not edit manually.\n");
        out.append("\n");
        out.append("package ").append(packageName).append(";\n");
        out.append('\n');
        for (String imp : imports.sorted()) {
            out.append("import ").append(imp).append(";\n");
        }
        out.append('\n');
        out.append(body);
        return out.toString();
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** Map an ABI type string to a Java type, adding the required import. */
    private static String javaType(String abiType, Imports imports) {
        return switch (abiType) {
            case "bigint", "int" -> "BigInteger"; // already imported at top
            case "boolean", "bool" -> "boolean";
            case "Sig" -> {
                imports.add("runar.lang.types.Sig");
                yield "Sig";
            }
            case "PubKey" -> {
                imports.add("runar.lang.types.PubKey");
                yield "PubKey";
            }
            case "Addr" -> {
                imports.add("runar.lang.types.Addr");
                yield "Addr";
            }
            case "ByteString", "Ripemd160", "Sha256", "Point", "SigHashPreimage" -> {
                imports.add("runar.lang.types.ByteString");
                yield "ByteString";
            }
            default -> "Object";
        };
    }

    /**
     * Expression converting a user-facing typed value into the raw
     * {@code Object} shape the SDK's call/ctor layer expects.
     */
    private static String toSdkValue(String name, String abiType) {
        return switch (abiType) {
            case "bigint", "int" -> name;
            case "boolean", "bool" -> name;
            case "Sig", "PubKey", "Addr", "ByteString", "Ripemd160", "Sha256", "Point", "SigHashPreimage" ->
                name + ".toHex()";
            default -> name;
        };
    }

    /** Drop-in parity with TS/Go {@code isTerminalMethod}. */
    private static boolean isTerminal(ABIMethod m, boolean isStateful) {
        if (!isStateful) return true;
        if (m.isTerminal() != null) return m.isTerminal();
        for (ABIParam p : m.params()) {
            if ("_changePKH".equals(p.name())) return false;
        }
        return true;
    }

    /** Drop-in parity with TS/Go {@code classifyParams}. */
    private static List<ClassifiedParam> classify(List<ABIParam> params, boolean isStateful) {
        List<ClassifiedParam> out = new ArrayList<>(params.size());
        for (ABIParam p : params) {
            boolean hidden = "Sig".equals(p.type())
                || (isStateful && "SigHashPreimage".equals(p.type()));
            boolean internal = isStateful
                && ("SigHashPreimage".equals(p.type())
                    || "_changePKH".equals(p.name())
                    || "_changeAmount".equals(p.name())
                    || "_newAmount".equals(p.name()));
            out.add(new ClassifiedParam(p.name(), p.type(), hidden, internal));
        }
        return out;
    }

    private static List<ABIMethod> publicMethods(RunarArtifact artifact) {
        List<ABIMethod> out = new ArrayList<>();
        for (ABIMethod m : artifact.abi().methods()) {
            if (m.isPublic()) out.add(m);
        }
        return out;
    }

    private static final Set<String> RESERVED = Set.of(
        "contract", "deploy", "provider", "signer", "inner", "state"
    );

    /**
     * Avoid collision with the wrapper's reserved method names. Parity
     * with the TS/Go {@code safeMethodName} helper.
     */
    private static String safeMethodName(String name) {
        if (RESERVED.contains(name)) {
            return "call" + Character.toUpperCase(name.charAt(0)) + name.substring(1);
        }
        return name;
    }

    // ---------------------------------------------------------------------

    private static final class ClassifiedParam {
        final String name;
        final String abiType;
        /** Auto-computed by SDK, elided from user signature, passed as null in args. */
        final boolean hidden;
        /** Fully SDK-internal, never passed in args (stateful-only preimages/change params). */
        final boolean internal;

        ClassifiedParam(String name, String abiType, boolean hidden, boolean internal) {
            this.name = name;
            this.abiType = abiType;
            this.hidden = hidden;
            this.internal = internal;
        }
    }

    private static final class Imports {
        private final Set<String> set = new LinkedHashSet<>();

        void add(String fqn) {
            set.add(fqn);
        }

        List<String> sorted() {
            List<String> list = new ArrayList<>(set);
            Collections.sort(list);
            return list;
        }
    }
}
