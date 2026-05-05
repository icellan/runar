package runar.anfdriver;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import runar.lang.sdk.AnfInterpreter;
import runar.lang.sdk.AnfInterpreter.DataOutput;
import runar.lang.sdk.AnfInterpreter.ExecutionResult;

/**
 * ANF interpreter parity driver — Java SDK.
 *
 * <p>Spec: {@code ../PROTOCOL.md}.
 *
 * <p>Reads a single JSON input file (path in {@code argv[0]}), invokes the
 * Java SDK's {@link AnfInterpreter#computeNewStateAndDataOutputs} entry point,
 * and prints a single JSON output object on stdout. Exit 0 on success,
 * non-zero on any error. No partial output is printed on error.
 *
 * <p>Mirrors the Python ({@code drivers/python/driver.py}) and Ruby
 * ({@code drivers/ruby/driver.rb}) drivers — including the {@code anfPath}
 * vs {@code case} fallback logic, since the cross-interpreter inputs
 * checked into the repo currently use the shorter {@code case} form.
 */
public final class Driver {

    private static final Pattern BIGINT_RE = Pattern.compile("^-?\\d+n$");

    private Driver() {}

    public static void main(String[] args) {
        try {
            run(args);
        } catch (Throwable t) {
            System.err.println("driver error: " + t.getClass().getSimpleName() + ": " + t.getMessage());
            if (System.getenv("DEBUG") != null) {
                t.printStackTrace(System.err);
            }
            System.exit(1);
        }
    }

    private static void run(String[] args) throws IOException {
        // Parse flags: optional --mode=strict (or --mode=lenient, the default).
        // Anything else is the positional input file. Order is irrelevant.
        boolean strict = false;
        String inputArg = null;
        for (String a : args) {
            if ("--mode=strict".equals(a)) {
                strict = true;
            } else if ("--mode=lenient".equals(a)) {
                strict = false;
            } else if (a.startsWith("--")) {
                System.err.println("unknown flag: " + a);
                System.exit(2);
                return;
            } else {
                if (inputArg != null) {
                    System.err.println("usage: java -jar runar-anf-driver.jar [--mode=strict] <input-json-file>");
                    System.exit(2);
                    return;
                }
                inputArg = a;
            }
        }
        if (inputArg == null) {
            System.err.println("usage: java -jar runar-anf-driver.jar [--mode=strict] <input-json-file>");
            System.exit(2);
            return;
        }

        Path inputPath = Paths.get(inputArg).toAbsolutePath();
        String inputJson = Files.readString(inputPath);
        Map<String, Object> input = MiniJson.asObject(MiniJson.parse(inputJson));

        Path anfPath = resolveAnfPath(input, inputPath);
        String methodName = MiniJson.asString(input.get("methodName"));

        Map<String, Object> currentStateRaw = MiniJson.asObject(input.get("currentState"));
        Map<String, Object> argsRaw = MiniJson.asObject(input.get("args"));
        List<Object> ctorArgsRaw = MiniJson.asArray(input.get("constructorArgs"));

        @SuppressWarnings("unchecked")
        Map<String, Object> currentState = (Map<String, Object>) decodeBigints(currentStateRaw);
        @SuppressWarnings("unchecked")
        Map<String, Object> methodArgs = (Map<String, Object>) decodeBigints(argsRaw);
        @SuppressWarnings("unchecked")
        List<Object> constructorArgs = (List<Object>) decodeBigints(ctorArgsRaw);

        String anfJson = Files.readString(anfPath);
        Map<String, Object> anf = MiniJson.asObject(MiniJson.parse(anfJson));

        ExecutionResult result;
        try {
            result = strict
                ? AnfInterpreter.executeStrict(anf, methodName, currentState, methodArgs, constructorArgs)
                : AnfInterpreter.computeNewStateAndDataOutputs(anf, methodName, currentState, methodArgs, constructorArgs);
        } catch (AnfInterpreter.AssertionFailureException ex) {
            // Strict-mode assertion failure: emit the standard envelope so the
            // cross-tier parity test can byte-compare. Real driver errors
            // (missing IR, malformed input) still escape to the outer catch.
            Map<String, Object> failure = new LinkedHashMap<>();
            failure.put("error", "AssertionFailureError");
            failure.put("methodName", ex.methodName());
            failure.put("bindingName", ex.bindingName());
            System.out.println(MiniJson.toJson(failure));
            return;
        }

        Map<String, Object> output = new LinkedHashMap<>();
        output.put("state", encodeBigints(result.newState));

        List<Object> outDataOutputs = new ArrayList<>(result.dataOutputs.size());
        for (DataOutput d : result.dataOutputs) {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("satoshis", d.satoshis() + "n");
            o.put("script", d.script() == null ? "" : d.script());
            outDataOutputs.add(o);
        }
        output.put("dataOutputs", outDataOutputs);

        List<Object> outRawOutputs = new ArrayList<>(result.rawOutputs.size());
        for (DataOutput d : result.rawOutputs) {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("satoshis", d.satoshis() + "n");
            o.put("script", d.script() == null ? "" : d.script());
            outRawOutputs.add(o);
        }
        output.put("rawOutputs", outRawOutputs);

        // Single trailing newline for parity with the Python/Ruby drivers.
        System.out.println(MiniJson.toJson(output));
    }

    /**
     * Resolve the ANF IR path. Prefer the explicit {@code anfPath} field;
     * fall back to {@code case} (mapping to
     * {@code conformance/tests/<case>/expected-ir.json}).
     */
    private static Path resolveAnfPath(Map<String, Object> input, Path inputFile) {
        Object anfPathVal = input.get("anfPath");
        if (anfPathVal instanceof String s && !s.isEmpty()) {
            return Paths.get(s).toAbsolutePath();
        }
        Object caseVal = input.get("case");
        if (!(caseVal instanceof String caseName) || caseName.isEmpty()) {
            throw new IllegalArgumentException(
                "input JSON missing both 'anfPath' and 'case' fields"
            );
        }
        // Walk up from the input file to find the conformance/ root, then
        // descend into tests/<case>/expected-ir.json.
        Path cur = inputFile.getParent();
        Path conformanceRoot = null;
        while (cur != null) {
            if ("conformance".equals(cur.getFileName() == null ? "" : cur.getFileName().toString())) {
                conformanceRoot = cur;
                break;
            }
            cur = cur.getParent();
        }
        if (conformanceRoot == null) {
            throw new IllegalArgumentException(
                "could not locate conformance/ directory walking up from " + inputFile.getParent()
            );
        }
        return conformanceRoot.resolve("tests").resolve(caseName).resolve("expected-ir.json");
    }

    /** Recursively decode {@code "Xn"} strings into {@link BigInteger}. */
    private static Object decodeBigints(Object v) {
        if (v instanceof String s && BIGINT_RE.matcher(s).matches()) {
            return new BigInteger(s.substring(0, s.length() - 1));
        }
        if (v instanceof List<?> l) {
            List<Object> out = new ArrayList<>(l.size());
            for (Object item : l) out.add(decodeBigints(item));
            return out;
        }
        if (v instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                out.put(String.valueOf(e.getKey()), decodeBigints(e.getValue()));
            }
            return out;
        }
        return v;
    }

    /**
     * Recursively re-encode integer-shaped values as {@code "Xn"} strings.
     *
     * <p>The Java SDK returns state values as a mix of {@link BigInteger}
     * (for bigints), {@link Boolean}, raw {@link String} (for hex
     * ByteString fields), and possibly {@link Long}/{@link Integer} that
     * leak through {@link MiniJson}'s number parser. Encode every integer
     * shape consistently.
     */
    private static Object encodeBigints(Object v) {
        if (v == null) return null;
        if (v instanceof Boolean) return v;
        if (v instanceof BigInteger bi) return bi.toString() + "n";
        if (v instanceof Long l) return l.toString() + "n";
        if (v instanceof Integer i) return i.toString() + "n";
        if (v instanceof List<?> l) {
            List<Object> out = new ArrayList<>(l.size());
            for (Object item : l) out.add(encodeBigints(item));
            return out;
        }
        if (v instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                out.put(String.valueOf(e.getKey()), encodeBigints(e.getValue()));
            }
            return out;
        }
        return v;
    }
}
