package runar.sdkdriver;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import runar.lang.sdk.Inscription;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;

/**
 * Cross-SDK conformance driver for the Java {@code runar-java} SDK.
 *
 * <p>Mirrors the per-SDK driver contract established by
 * {@code conformance/sdk-output/tools/go-sdk-tool.go},
 * {@code py-sdk-tool.py}, {@code rs-sdk-tool}, etc.
 *
 * <p>Invocation: {@code java -jar java-sdk-driver-all.jar <input.json>}.
 * Reads the shared conformance input format:
 * <pre>
 *   {
 *     "artifact":        { ... RunarArtifact ... },
 *     "constructorArgs": [ { "type": "bigint"|"bool"|"...", "value": "..." }, ... ],
 *     "inscription":     { "contentType": "...", "data": "<hex>" }   // optional
 *   }
 * </pre>
 * and prints {@link RunarContract#lockingScript()} on stdout with no
 * trailing newline.
 */
public final class Driver {

    private Driver() {}

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: java-sdk-driver <input.json>");
            System.exit(1);
        }

        String raw = Files.readString(Paths.get(args[0]));
        Object root = MiniJson.parse(raw);
        Map<String, Object> input = MiniJson.asObject(root);

        Map<String, Object> artifactMap = MiniJson.asObject(input.get("artifact"));
        RunarArtifact artifact = RunarArtifact.fromJson(MiniJson.toJson(artifactMap));

        List<Object> ctorArgs = new ArrayList<>();
        Object rawArgs = input.get("constructorArgs");
        if (rawArgs instanceof List<?> l) {
            for (Object entry : l) {
                Map<String, Object> typed = MiniJson.asObject(entry);
                ctorArgs.add(convertArg(
                    MiniJson.asString(typed.get("type")),
                    MiniJson.asString(typed.get("value"))
                ));
            }
        }

        RunarContract contract = new RunarContract(artifact, ctorArgs);

        Object rawInsc = input.get("inscription");
        if (rawInsc != null) {
            Map<String, Object> ins = MiniJson.asObject(rawInsc);
            contract.withInscription(new Inscription(
                MiniJson.asString(ins.get("contentType")),
                MiniJson.asString(ins.get("data"))
            ));
        }

        System.out.print(contract.lockingScript());
    }

    /**
     * Mirrors {@code convertArg} in the Go / Python / Rust / Ruby
     * drivers: map the typed-string JSON arg to the native SDK type
     * expected by {@code RunarContract}'s constructor / method params.
     */
    private static Object convertArg(String type, String value) {
        if (type == null) return value;
        switch (type) {
            case "bigint":
            case "int":
                return new BigInteger(value);
            case "bool":
                return "true".equals(value);
            default:
                // ByteString, PubKey, Addr, Sig, Ripemd160, Sha256, Point — hex strings
                return value;
        }
    }
}
