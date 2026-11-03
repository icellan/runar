package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import runar.compiler.Cli;

/**
 * N-189: the off-chain scriptCode {@code RunarContract.call} hands the ANF
 * interpreter (what {@code extractScriptCode(txPreimage)} returns while the
 * SDK predicts the post-state) must be the scriptCode field of the BIP-143
 * preimage the call actually signs: the SPENT UTXO's locking script after the
 * OP_CODESEPARATOR, code AND the {@code OP_RETURN <state>} tail. R67 built it
 * from the bare template codePart, so a method whose post-state depends on
 * its own scriptCode committed a continuation the covenant's hashOutputs
 * check rejects (shown on @bsv/sdk Spend by
 * {@code packages/runar-sdk/src/__tests__/n189-scriptcode-intent-includes-state.test.ts}).
 *
 * <p>Proves: for a contract whose new state is
 * {@code len(extractScriptCode(txPreimage))}, the committed state equals
 * CompactSize(len) + len of the spent UTXO script after the code separator,
 * i.e. the scriptCode field {@code OpPushTx.preimage} signs (the signing path
 * slices the same UTXO script with the same {@code getCodeSepIndex} /
 * {@code subscriptAfterCodeSep}).
 *
 * <p>Does NOT prove: on-chain acceptance (Java ships no ScriptVM), or extra
 * contract inputs of a multi-input call (each is spent by its own preimage).
 */
class N189ScriptCodeIntentTest {

    private static final String PRIV =
        "0000000000000000000000000000000000000000000000000000000000000003";

    private static final String SRC = String.join("\n",
        "import { StatefulSmartContract, extractScriptCode, len } from 'runar-lang';",
        "",
        "class ScLen extends StatefulSmartContract {",
        "  n: bigint;",
        "",
        "  constructor(n: bigint) {",
        "    super(n);",
        "    this.n = n;",
        "  }",
        "",
        "  public rec(): void {",
        "    this.n = len(extractScriptCode(this.txPreimage));",
        "  }",
        "}", "");

    private static RunarArtifact compile() throws Exception {
        Path dir = Files.createTempDirectory("n189-java");
        Path src = dir.resolve("ScLen.runar.ts");
        Path out = dir.resolve("artifact.json");
        try {
            Files.writeString(src, SRC);
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int exit = new Cli(
                new PrintStream(stdout, true, StandardCharsets.UTF_8),
                new PrintStream(stderr, true, StandardCharsets.UTF_8)
            ).run(new String[] {"--source", src.toString(), "--emit-artifact", out.toString()});
            assertEquals(0, exit, stderr.toString(StandardCharsets.UTF_8));
            return RunarArtifact.fromJson(Files.readString(out));
        } finally {
            Files.deleteIfExists(out);
            Files.deleteIfExists(src);
            Files.deleteIfExists(dir);
        }
    }

    @Test
    void committedStateIsLengthOfSignedScriptCode() throws Exception {
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        provider.addUtxo(signer.address(),
            new UTXO("aa".repeat(32), 0, 100_000L, ScriptUtils.buildP2PKHScript(signer.address())));

        RunarContract contract = new RunarContract(compile(), List.of(BigInteger.ZERO));
        contract.deploy(provider, signer, 5_000L, signer.address());

        String spentScript = contract.currentUtxo().scriptHex();
        int codeSepIdx = contract.getCodeSepIndex(0);
        String body = codeSepIdx >= 0
            ? RunarContract.subscriptAfterCodeSep(spentScript, codeSepIdx)
            : spentScript;
        int bodyLen = body.length() / 2;
        long signedScriptCodeLen = ScriptUtils.encodeVarInt(bodyLen).length() / 2 + bodyLen;

        contract.call("rec", List.of(), null, provider, signer);

        assertEquals(BigInteger.valueOf(signedScriptCodeLen), contract.state().get("n"),
            "committed n must equal len(signed preimage scriptCode)");
    }
}
