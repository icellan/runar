package runar.lang.sdk;

import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * R-062 — the unsound-primitive gate on the WALLET funding path (Java).
 *
 * <p>These tests cover the {@link WalletProvider}-as-Provider path: a
 * wallet-backed deploy through {@link RunarContract#deploy}, which runs both the
 * DoS script-size bound and {@link UnsoundPrimitives#assertAcknowledged}. The
 * second funding path, {@link RunarContract#deployWithWallet} (BRC-100
 * {@code createAction}, GK-GAP-014), carries the same two guards and is pinned
 * in {@code WalletBrc100ActionsTest}. Three cases, because
 * over-rejection here would break every legitimate wallet deploy: the refusal,
 * an ordinary artifact, and an acknowledged unsound one.
 */
class R062WalletDeployGateTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
    private static final String PATH = "runar/m/0";

    private static RunarArtifact artifact(String... unsound) {
        return new RunarArtifact(
            "runar-v1.0.0-rc.1", "1.0.0-rc.1-go", "Sp1Rollup", null,
            new RunarArtifact.ABI(new RunarArtifact.ABIConstructor(List.of()), List.of()),
            "51", "OP_1", "2026-09-13T00:00:00Z",
            List.of(), List.of(), List.of(), null, List.of(), null,
            List.of(unsound)
        );
    }

    /** A wallet-backed provider+signer with one funding coin it can spend. */
    private static WalletProvider fundedWalletProvider() {
        LocalSigner inner = new LocalSigner(PRIV);
        MockBRC100Wallet wallet = new MockBRC100Wallet().register(PATH, inner);
        MockProvider delegate = new MockProvider();
        delegate.addUtxo(inner.address(), new UTXO(
            "a1".repeat(32), 0, 100_000L,
            ScriptUtils.buildP2PKHScript(inner.address())
        ));
        return new WalletProvider(wallet, delegate, PATH);
    }

    @Test
    void refusesUnacknowledgedUnsoundArtifactOnTheWalletBackedPath() {
        WalletProvider wp = fundedWalletProvider();
        RunarContract contract = new RunarContract(artifact("verifySP1FRI"), List.of());

        var e = assertThrows(
            UnsoundPrimitives.UnsoundPrimitiveError.class,
            () -> contract.deploy(wp, wp, new DeployOptions().withSatoshis(1L))
        );
        assertTrue(e.getMessage().contains("verifySP1FRI"), e.getMessage());
        assertTrue(e.getMessage().contains("Sp1Rollup.deploy"), e.getMessage());
        assertTrue(e.getMessage().contains("withAcknowledgeUnsound"), e.getMessage());
        assertEquals(List.of("verifySP1FRI"), e.missing);
        assertNull(contract.currentUtxo(), "no UTXO may be tracked after a refusal");
    }

    @Test
    void controlOrdinaryArtifactStillFundsThroughTheWallet() {
        WalletProvider wp = fundedWalletProvider();
        RunarContract contract = new RunarContract(artifact(), List.of());

        RunarContract.DeployOutcome out =
            contract.deploy(wp, wp, new DeployOptions().withSatoshis(1L));

        assertNotNull(out.txid());
        assertFalse(out.txid().isEmpty());
        assertNotNull(contract.currentUtxo());
    }

    @Test
    void controlAcknowledgedUnsoundArtifactStillFundsThroughTheWallet() {
        WalletProvider wp = fundedWalletProvider();
        RunarContract contract = new RunarContract(artifact("verifySP1FRI"), List.of());

        RunarContract.DeployOutcome out = contract.deploy(wp, wp,
            new DeployOptions().withSatoshis(1L).withAcknowledgeUnsound(List.of("verifySP1FRI")));

        assertNotNull(out.txid());
        assertFalse(out.txid().isEmpty());
        assertNotNull(contract.currentUtxo());
    }

    @Test
    void partialAcknowledgementIsStillARefusal() {
        WalletProvider wp = fundedWalletProvider();
        RunarContract contract = new RunarContract(
            artifact("verifySP1FRI", "someFutureStub"), List.of());

        var e = assertThrows(
            UnsoundPrimitives.UnsoundPrimitiveError.class,
            () -> contract.deploy(wp, wp, new DeployOptions()
                .withSatoshis(1L).withAcknowledgeUnsound(List.of("verifySP1FRI")))
        );
        assertEquals(List.of("someFutureStub"), e.missing);
        assertNull(contract.currentUtxo());
    }

    /**
     * Structural assertion: the only wallet-owned funding entry point on
     * {@link RunarContract} is {@code deployWithWallet} (GK-GAP-014), whose
     * script-size and R-062 guards are pinned in
     * {@code WalletBrc100ActionsTest.deployWithWalletRefuses*}. If another one
     * is ever added, this fails and whoever adds it has to give it the same
     * guards {@code deploy} carries.
     */
    @Test
    void theOnlyWalletFundingPathIsTheGuardedDeployWithWallet() {
        java.util.Set<String> found = new java.util.TreeSet<>();
        for (var m : RunarContract.class.getMethods()) {
            String n = m.getName().toLowerCase(java.util.Locale.ROOT);
            if (n.contains("withwallet") || n.contains("createaction")) {
                found.add(m.getName());
            }
        }
        assertEquals(java.util.Set.of("deployWithWallet"), found,
            "a new wallet funding path appeared — it must run "
                + "ScriptSizeExceededError.assertScriptHexUnderLimit and "
                + "UnsoundPrimitives.assertAcknowledged, and needs its own R-062 tests");
        assertNotNull(HexFormat.of());
    }
}
