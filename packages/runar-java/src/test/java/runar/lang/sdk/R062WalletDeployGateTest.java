package runar.lang.sdk;

import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * R-062 — the unsound-primitive gate on the WALLET funding path (Java).
 *
 * <p>Java is the second tier that was already correct, for a structural reason:
 * there is no {@code deployWithWallet} / {@code createAction} second funding
 * path at all. {@link WalletProvider} is a Provider+Signer adapter over a
 * {@link BRC100Wallet}, so a wallet-backed deploy goes through the ONE
 * {@link RunarContract#deploy} that already runs both the DoS script-size bound
 * and {@link UnsoundPrimitives#assertAcknowledged}.
 *
 * <p>These tests pin that, so a future {@code createAction} path cannot be
 * added without noticing what it has to carry. Three cases, because
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
     * Structural assertion: the Java SDK exposes no second, wallet-owned
     * funding entry point. If one is ever added, this fails and whoever adds it
     * has to give it the same guards {@code deploy} carries.
     */
    @Test
    void thereIsNoSecondWalletFundingPath() {
        for (var m : RunarContract.class.getMethods()) {
            String n = m.getName().toLowerCase(java.util.Locale.ROOT);
            assertFalse(
                n.contains("deploywithwallet") || n.contains("createaction"),
                "a second wallet funding path appeared (" + m.getName()
                    + ") — it must run ScriptSizeExceededError.assertScriptHexUnderLimit "
                    + "and UnsoundPrimitives.assertAcknowledged, and needs its own R-062 tests"
            );
        }
        assertNotNull(HexFormat.of());
    }
}
