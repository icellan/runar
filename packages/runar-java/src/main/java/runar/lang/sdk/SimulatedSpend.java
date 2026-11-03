package runar.lang.sdk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import runar.compiler.Cli;

/**
 * Builds the spending transaction an off-chain stateful call produces and
 * returns its BIP-143 preimage, so {@code runar.lang.runtime.ContractSimulator}
 * can check a test-supplied preimage against the transaction it claims to sign
 * (F-129). The sighash bytes come from {@link OpPushTx#preimage}, the same code
 * {@link RunarContract} uses for a real call; the locking / continuation
 * scripts come from {@link ContractScript} and {@link StateSerializer}.
 */
public final class SimulatedSpend {

    private SimulatedSpend() {}

    /** One output of the simulated spending transaction. */
    public record Out(long satoshis, String scriptHex) {}

    /** The contract's locking script for the given constructor args and state. */
    public static String lockingScript(RunarArtifact artifact, List<Object> constructorArgs, Map<String, Object> state) {
        return ContractScript.renderLockingScript(artifact, constructorArgs, state);
    }

    /** A state continuation: the locking script's code part, OP_RETURN, then {@code state}. */
    public static String continuationScript(RunarArtifact artifact, String lockingScript, Map<String, Object> state) {
        return ContractScript.extractCodePart(lockingScript) + "6a"
            + StateSerializer.serialize(artifact.stateFields(), state);
    }

    /** State field names in {@link RunarArtifact.StateField#index()} order (addOutput's positional order). */
    public static List<String> stateFieldNamesInOrder(RunarArtifact artifact) {
        return artifact.stateFields().stream()
            .sorted(Comparator.comparingInt(RunarArtifact.StateField::index))
            .map(RunarArtifact.StateField::name)
            .toList();
    }

    /**
     * BIP-143 preimage of input 0 of a one-input transaction spending
     * {@code lockingScript} through public method {@code methodName}. The
     * scriptCode is the locking script after the method's OP_CODESEPARATOR,
     * located exactly as {@link RunarContract} locates it for a real call.
     */
    public static byte[] preimage(
        RunarArtifact artifact,
        String methodName,
        List<Object> constructorArgs,
        String lockingScript,
        List<Out> outputs,
        int version,
        String prevTxid,
        int prevVout,
        long amount,
        long sequence,
        int locktime,
        int sigHashType
    ) {
        RunarContract rc = new RunarContract(artifact, constructorArgs);
        rc.setCurrentUtxo(new UTXO(prevTxid, prevVout, amount, lockingScript));
        int methodIndex = rc.findPublicMethodIndex(methodName);
        if (methodIndex < 0) {
            throw new IllegalArgumentException("no public method '" + methodName + "' in artifact "
                + artifact.contractName());
        }
        int codeSepIdx = rc.getCodeSepIndex(methodIndex);
        String scriptCode = codeSepIdx >= 0
            ? RunarContract.subscriptAfterCodeSep(lockingScript, codeSepIdx)
            : lockingScript;

        RawTx tx = new RawTx();
        tx.version = version;
        tx.locktime = locktime;
        tx.addInput(prevTxid, prevVout, "");
        tx.setAllSequences(sequence);
        for (Out o : outputs) tx.addOutput(o.satoshis(), o.scriptHex());
        return OpPushTx.preimage(tx, 0, ScriptUtils.hexToBytes(scriptCode), amount, sigHashType);
    }

    /** Compile a Rúnar source file to its deployable artifact (in-process Java compiler). */
    public static RunarArtifact compile(Path source) throws IOException {
        return compile(Files.readString(source), source.getFileName().toString());
    }

    /**
     * Compile Rúnar {@code source} to its deployable artifact by running the
     * Java compiler's {@code --source … --emit-artifact} path in-process.
     * {@code fileName} selects the frontend by extension.
     */
    public static RunarArtifact compile(String source, String fileName) throws IOException {
        Path dir = Files.createTempDirectory("runar-sim-");
        try {
            Path src = dir.resolve(fileName);
            Path art = dir.resolve("artifact.json");
            Files.writeString(src, source);
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            int rc = new Cli(new PrintStream(new ByteArrayOutputStream()), new PrintStream(err, true, StandardCharsets.UTF_8))
                .run(new String[] {"--source", src.toString(), "--emit-artifact", art.toString()});
            if (rc != 0) {
                throw new CompileException("compile failed for " + fileName + " (exit " + rc + ")",
                    List.of(err.toString(StandardCharsets.UTF_8)), null);
            }
            return RunarArtifact.fromJson(Files.readString(art));
        } finally {
            try (var walk = Files.walk(dir)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }
}
