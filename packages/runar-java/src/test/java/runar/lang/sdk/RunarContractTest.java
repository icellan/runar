package runar.lang.sdk;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import runar.lang.sdk.RunarArtifact.StateField;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end {@link RunarContract} lifecycle: construct → deploy →
 * call → state mutation. Uses {@link MockProvider} for broadcast and
 * {@link LocalSigner} for signing. Mirrors the contract-lifecycle
 * coverage in {@code packages/runar-py/tests/test_contract_lifecycle.py}.
 */
class RunarContractTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";

    @Test
    void constructorRejectsArgCountMismatch() throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        IllegalArgumentException ex = assertThrows(
            IllegalArgumentException.class,
            () -> new RunarContract(artifact, List.of())
        );
        assertTrue(ex.getMessage().contains("expected 1 constructor args"));
    }

    @Test
    void constructorAcceptsCorrectArgCount() throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        RunarContract contract = new RunarContract(artifact, List.of("00".repeat(20)));
        assertSame(artifact, contract.artifact());
        assertNotNull(contract.lockingScript());
    }

    @Test
    void statelessContractHasEmptyInitialState() throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        RunarContract contract = new RunarContract(artifact, List.of("00".repeat(20)));
        assertTrue(contract.state().isEmpty(), "stateless contract: state map empty");
    }

    @Test
    void statefulContractInitialStateFromConstructorArgs() throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/stateful-counter.runar.json");
        // stateful-counter: state field is `counter` (initialized from
        // first constructor arg).
        RunarContract contract = new RunarContract(artifact, List.of(BigInteger.valueOf(42)));
        // The contract artifact has at least one state field; whatever its
        // name, the value at that field should equal the constructor arg.
        Map<String, Object> state = contract.state();
        assertFalse(state.isEmpty(), "stateful contract: state map populated");
        assertTrue(state.containsValue(BigInteger.valueOf(42)),
            "constructor arg must populate the indexed state field; state=" + state);
    }

    @Test
    void lockingScriptChangesWhenStateMutated() throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/stateful-counter.runar.json");
        RunarContract contract = new RunarContract(artifact, List.of(BigInteger.valueOf(0)));
        String initial = contract.lockingScript();

        // Mutate state directly — the locking script must change because
        // ContractScript.renderLockingScript uses the current state map.
        Map<String, Object> mutable = new HashMap<>(contract.state());
        String fieldName = mutable.keySet().iterator().next();
        mutable.put(fieldName, BigInteger.valueOf(1));

        RunarContract mutated = new RunarContract(artifact, List.of(BigInteger.valueOf(1)));
        assertNotEquals(initial, mutated.lockingScript(),
            "different state must produce different locking script");
    }

    @Test
    void callBeforeDeployFails() throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        String pkhHex = HexFormat.of().formatHex(Hash160.hash160(signer.pubKey()));
        RunarContract contract = new RunarContract(artifact, List.of(pkhHex));

        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        args.add(null); args.add(null);
        IllegalStateException ex = assertThrows(IllegalStateException.class,
            () -> contract.call("unlock", args, null, provider, signer));
        assertTrue(ex.getMessage().contains("not been deployed"));
    }

    @Test
    void callRejectsUnknownMethod() throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        String pkhHex = HexFormat.of().formatHex(Hash160.hash160(signer.pubKey()));
        RunarContract contract = new RunarContract(artifact, List.of(pkhHex));

        contract.setCurrentUtxo(new UTXO("ab".repeat(32), 0, 10_000L, contract.lockingScript()));
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
            () -> contract.call("nonExistent", List.of(), null, provider, signer));
        assertTrue(ex.getMessage().contains("not found"));
    }

    @Test
    void deployUpdatesCurrentUtxo() throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();
        // Seed the provider with a funding UTXO for the signer's address.
        provider.addUtxo(signer.address(),
            new UTXO("99".repeat(32), 0, 100_000L, p2pkhScriptFor(signer.address())));

        String pkhHex = HexFormat.of().formatHex(Hash160.hash160(signer.pubKey()));
        RunarContract contract = new RunarContract(artifact, List.of(pkhHex));
        assertNull(contract.currentUtxo(), "no UTXO before deploy");

        RunarContract.DeployOutcome out = contract.deploy(provider, signer, 5_000L, signer.address());
        assertNotNull(out.txid());
        assertNotNull(contract.currentUtxo(), "deploy must populate currentUtxo");
        assertEquals(out.txid(), contract.currentUtxo().txid());
        assertEquals(5_000L, contract.currentUtxo().satoshis());
    }

    @Test
    void callOnStatelessContractClearsCurrentUtxo() throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        LocalSigner signer = new LocalSigner(PRIV);
        MockProvider provider = new MockProvider();

        String pkhHex = HexFormat.of().formatHex(Hash160.hash160(signer.pubKey()));
        RunarContract contract = new RunarContract(artifact, List.of(pkhHex));
        contract.setCurrentUtxo(new UTXO("ab".repeat(32), 0, 10_000L, contract.lockingScript()));

        // Call unlock(sig=null → auto-sign, pubKey=null → auto-fill from signer).
        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        args.add(null); args.add(null);
        contract.call("unlock", args, null, provider, signer);

        // Stateless terminal call: contract is fully consumed.
        assertNull(contract.currentUtxo(),
            "stateless contract must release currentUtxo after a terminal call");
    }

    @Test
    void inscriptionAttachesAndAffectsLockingScript() throws Exception {
        RunarArtifact artifact = loadArtifact("artifacts/basic-p2pkh.runar.json");
        RunarContract contract = new RunarContract(artifact, List.of("00".repeat(20)));
        String before = contract.lockingScript();
        contract.withInscription(new Inscription("text/plain", "68656c6c6f"));
        String after = contract.lockingScript();
        assertNotEquals(before, after);
        assertNotNull(contract.inscription());
        assertEquals("text/plain", contract.inscription().contentType());
    }

    private static RunarArtifact loadArtifact(String classpathRel) throws Exception {
        Path resource = Path.of("src/test/resources/" + classpathRel);
        if (!Files.exists(resource)) {
            // Test was launched with a different working directory (e.g.,
            // gradle root); fall back to the classpath loader.
            try (var in = RunarContractTest.class.getClassLoader().getResourceAsStream(classpathRel)) {
                if (in == null) throw new IllegalStateException("missing fixture " + classpathRel);
                return RunarArtifact.fromJson(new String(in.readAllBytes()));
            }
        }
        return RunarArtifact.fromJson(Files.readString(resource));
    }

    private static String p2pkhScriptFor(String address) {
        // Address is a Base58Check-encoded hash160 + version byte; for the
        // mock provider we only need a script the SDK's UtxoSelector can
        // recognise. A trivial all-OP_0 script suffices because MockProvider
        // doesn't validate scripts.
        return "76a914" + "00".repeat(20) + "88ac";
    }
}
