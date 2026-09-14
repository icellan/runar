package runar.sdkdriver;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import runar.lang.sdk.DeployOptions;
import runar.lang.sdk.Inscription;
import runar.lang.sdk.LocalSigner;
import runar.lang.sdk.MockBRC100Wallet;
import runar.lang.sdk.MockProvider;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;
import runar.lang.sdk.ScriptUtils;
import runar.lang.sdk.UTXO;
import runar.lang.sdk.UnsoundPrimitives;
import runar.lang.sdk.WalletProvider;

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
            // N-043: a refused attach is a RESULT, not a crash — exit non-zero
            // with the reason on stderr so the runner can compare the refusal
            // verdict across all seven tiers.
            try {
                contract.withInscription(new Inscription(
                    MiniJson.asString(ins.get("contentType")),
                    MiniJson.asString(ins.get("data"))
                ));
            } catch (IllegalArgumentException e) {
                System.err.println(e.getMessage());
                System.exit(1);
            }
        }

        Object rawWalletDeploy = input.get("walletDeploy");
        if (rawWalletDeploy != null) {
            runWalletDeploy(contract, MiniJson.asObject(rawWalletDeploy));
        }

        System.out.print(contract.lockingScript());
    }

    /**
     * R-062 — drive the tier's WALLET funding path so all seven tiers can be
     * asked to agree on accept-vs-refuse for one artifact.
     *
     * <p>Java has no {@code deployWithWallet} / {@code createAction} second
     * funding path: {@link WalletProvider} is a Provider+Signer adapter over a
     * BRC-100 wallet, so a wallet-backed deploy goes through the ONE
     * {@link RunarContract#deploy} that already carries the script-size bound
     * and the unsound-primitive gate. That is the path exercised here.
     *
     * <p>A refusal is a RESULT, not a crash — exit non-zero with the reason on
     * stderr so the runner can compare the verdict across all seven tiers.
     */
    private static void runWalletDeploy(RunarContract contract, Map<String, Object> wd) {
        long satoshis = 1L;
        Object rawSats = wd.get("satoshis");
        if (rawSats instanceof Number n) satoshis = n.longValue();

        List<String> acknowledge = new ArrayList<>();
        Object rawAck = wd.get("acknowledgeUnsound");
        if (rawAck instanceof List<?> l) {
            for (Object entry : l) acknowledge.add(MiniJson.asString(entry));
        }

        LocalSigner inner = new LocalSigner(WALLET_DRIVER_PRIV);
        MockBRC100Wallet wallet = new MockBRC100Wallet().register(WALLET_PATH, inner);
        MockProvider delegate = new MockProvider();
        delegate.addUtxo(inner.address(), new UTXO(
            "ab".repeat(32), 0, 100_000L,
            ScriptUtils.buildP2PKHScript(inner.address())
        ));
        WalletProvider wp = new WalletProvider(wallet, delegate, WALLET_PATH);

        try {
            contract.deploy(wp, wp, new DeployOptions()
                .withSatoshis(satoshis)
                .withAcknowledgeUnsound(acknowledge));
        } catch (UnsoundPrimitives.UnsoundPrimitiveError e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }

    private static final String WALLET_DRIVER_PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
    private static final String WALLET_PATH = "runar/m/0";

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
            // `boolean` is the spelling the compiler's ABI carries; `bool`
            // is the alias some frontends use. Accept both (R-248).
            case "bool":
            case "boolean":
                return "true".equals(value);
            default:
                // ByteString, PubKey, Addr, Sig, Ripemd160, Sha256, Point — hex strings
                return value;
        }
    }
}
