package runar.lang.sdk;

import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * GK-GAP-014 — the BRC-100 action surface ported from the Go SDK
 * ({@code packages/runar-go/sdk_wallet.go}): {@code createAction},
 * {@code listOutputs}, {@code WalletProvider.ensureFunding} and
 * {@code RunarContract.deployWithWallet}. Java was the only one of the seven
 * SDKs without them. Each case mirrors a Go test in {@code sdk_wallet_test.go}.
 */
class WalletBrc100ActionsTest {

    private static final String PRIV =
        "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
    private static final String PATH = "runar/m/0";
    private static final String BASKET = "runar-test";

    private static String ownScript(LocalSigner s) {
        return "76a914" + HexFormat.of().formatHex(Hash160.hash160(s.pubKey())) + "88ac";
    }

    private static RunarArtifact artifact(String scriptHex, String... unsound) {
        return new RunarArtifact(
            "runar-v1.0.0-rc.1", "1.0.0-rc.1-go", "WalletDeployed", null,
            new RunarArtifact.ABI(new RunarArtifact.ABIConstructor(List.of()), List.of()),
            scriptHex, "OP_1", "2026-11-15T00:00:00Z",
            List.of(), List.of(), List.of(), null, List.of(), null,
            List.of(unsound)
        );
    }

    private static final class Fixture {
        final LocalSigner key = new LocalSigner(PRIV);
        final MockBRC100Wallet wallet = new MockBRC100Wallet().register(PATH, key);
        final WalletProvider wp = new WalletProvider(wallet, new MockProvider(), PATH, BASKET, null);
    }

    // ------------------------------------------------------------------
    // listOutputs-backed UTXO view (Go: GetUtxos)
    // ------------------------------------------------------------------

    @Test
    void walletUtxosKeepOnlySpendableOwnP2pkhOutputsWithAScript() {
        Fixture f = new Fixture();
        String own = ownScript(f.key);
        f.wallet.addOutput(BASKET, List.of("funding"), new WalletOutput(10_000, own, true, "aa".repeat(32) + ".0"));
        f.wallet.addOutput(BASKET, List.of("funding"), new WalletOutput(5_000, own, false, "bb".repeat(32) + ".1"));
        f.wallet.addOutput(BASKET, List.of("funding"),
            new WalletOutput(3_000, "76a914" + "ff".repeat(20) + "88ac", true, "cc".repeat(32) + ".0"));
        f.wallet.addOutput(BASKET, List.of("funding"), new WalletOutput(2_000, "", true, "dd".repeat(32) + ".2"));
        f.wallet.addOutput("other-basket", List.of("funding"), new WalletOutput(7_000, own, true, "ee".repeat(32) + ".3"));

        List<UTXO> utxos = f.wp.listWalletUtxos();

        assertEquals(1, utxos.size(), "only the spendable, own-key, scripted output in the basket: " + utxos);
        UTXO u = utxos.get(0);
        assertEquals("aa".repeat(32), u.txid());
        assertEquals(0, u.outputIndex());
        assertEquals(10_000L, u.satoshis());
        assertEquals(own, u.scriptHex());
    }

    @Test
    void walletUtxosAskTheWalletForTheFundingTagInTheConfiguredBasket() {
        Fixture f = new Fixture();
        f.wp.listWalletUtxos();
        MockBRC100Wallet.ListCall call = f.wallet.listCalls().get(0);
        assertEquals(BASKET, call.basket());
        assertEquals(List.of("funding"), call.tags());
        assertEquals(100, call.limit());
    }

    @Test
    void walletWithoutTheActionSurfaceFailsClosed() {
        BRC100Wallet signOnly = new BRC100Wallet() {
            @Override public byte[] sign(byte[] sighash, String p) { throw new AssertionError(); }
            @Override public byte[] pubKey(String p) { return new LocalSigner(PRIV).pubKey(); }
            @Override public String address(String p) { return new LocalSigner(PRIV).address(); }
        };
        WalletProvider wp = new WalletProvider(signOnly, new MockProvider(), PATH, BASKET, null);
        assertThrows(UnsupportedOperationException.class, wp::listWalletUtxos);
        assertThrows(UnsupportedOperationException.class, () -> wp.ensureFunding(1_000));
    }

    // ------------------------------------------------------------------
    // ensureFunding (Go: EnsureFunding)
    // ------------------------------------------------------------------

    @Test
    void ensureFundingCreatesNoActionWhenAlreadyFunded() {
        Fixture f = new Fixture();
        f.wallet.addOutput(BASKET, List.of("funding"),
            new WalletOutput(50_000, ownScript(f.key), true, "aa".repeat(32) + ".0"));
        f.wp.ensureFunding(10_000);
        assertEquals(0, f.wallet.createdActions().size());
    }

    @Test
    void ensureFundingCreatesOneP2pkhFundingOutputWhenShort() {
        Fixture f = new Fixture();
        f.wallet.addOutput(BASKET, List.of("funding"),
            new WalletOutput(4_000, ownScript(f.key), true, "aa".repeat(32) + ".0"));

        f.wp.ensureFunding(10_000);

        assertEquals(1, f.wallet.createdActions().size());
        MockBRC100Wallet.Action a = f.wallet.createdActions().get(0);
        assertEquals("fund contract deployment", a.description());
        assertEquals(1, a.outputs().size());
        WalletActionOutput o = a.outputs().get(0);
        assertEquals(10_000L, o.satoshis());
        assertEquals(ownScript(f.key), o.lockingScript());
        assertEquals(BASKET, o.basket());
        assertEquals(List.of("funding"), o.tags());

        // The mock wallet now holds the new output, so a second call is a no-op.
        f.wp.ensureFunding(10_000);
        assertEquals(1, f.wallet.createdActions().size());
    }

    @Test
    void ensureFundingUsesAConfiguredFundingTag() {
        LocalSigner key = new LocalSigner(PRIV);
        MockBRC100Wallet wallet = new MockBRC100Wallet().register(PATH, key);
        WalletProvider wp = new WalletProvider(wallet, new MockProvider(), PATH, BASKET, "fees");
        wp.ensureFunding(1_000);
        assertEquals(List.of("fees"), wallet.listCalls().get(0).tags());
        assertEquals(List.of("fees"), wallet.createdActions().get(0).outputs().get(0).tags());
    }

    @Test
    void ensureFundingPropagatesAWalletFailure() {
        Fixture f = new Fixture();
        f.wallet.failCreateAction(new IllegalStateException("wallet unavailable"));
        ProviderException e = assertThrows(ProviderException.class, () -> f.wp.ensureFunding(10_000));
        assertTrue(e.getMessage().contains("wallet unavailable"), e.getMessage());
    }

    // ------------------------------------------------------------------
    // deployWithWallet (Go: DeployWithWallet)
    // ------------------------------------------------------------------

    @Test
    void deployWithWalletCreatesTheContractOutputAndTracksTheUtxo() {
        Fixture f = new Fixture();
        RunarContract c = new RunarContract(artifact("51"), List.of());

        RunarContract.DeployWithWalletResult r = c.deployWithWallet(f.wp,
            new DeployWithWalletOptions(1_000L, "deploy test contract", "tokens", List.of("test"), null));

        assertEquals(64, r.txid().length());
        assertEquals(1, f.wallet.createdActions().size());
        MockBRC100Wallet.Action a = f.wallet.createdActions().get(0);
        assertEquals("deploy test contract", a.description());
        assertEquals(1, a.outputs().size());
        WalletActionOutput o = a.outputs().get(0);
        assertEquals(1_000L, o.satoshis());
        assertEquals("51", o.lockingScript());
        assertEquals("tokens", o.basket());
        assertEquals(List.of("test"), o.tags());

        UTXO u = c.currentUtxo();
        assertNotNull(u, "the deployed UTXO must be tracked");
        assertEquals(r.txid(), u.txid());
        assertEquals(0, u.outputIndex());
        assertEquals(1_000L, u.satoshis());
        assertEquals("51", u.scriptHex());
    }

    @Test
    void deployWithWalletDefaults() {
        Fixture f = new Fixture();
        RunarContract c = new RunarContract(artifact("51"), List.of());
        c.deployWithWallet(f.wp, null);
        WalletActionOutput o = f.wallet.createdActions().get(0).outputs().get(0);
        assertEquals(1L, o.satoshis(), "default is 1 satoshi");
        assertEquals(BASKET, o.basket(), "default basket is the provider's");
        assertEquals("deploy WalletDeployed", f.wallet.createdActions().get(0).description());
    }

    @Test
    void deployWithWalletRefusesAnUnacknowledgedUnsoundArtifactBeforeTheWallet() {
        Fixture f = new Fixture();
        RunarContract c = new RunarContract(artifact("51", "verifySP1FRI"), List.of());
        UnsoundPrimitives.UnsoundPrimitiveError e = assertThrows(UnsoundPrimitives.UnsoundPrimitiveError.class,
            () -> c.deployWithWallet(f.wp, new DeployWithWalletOptions(1_000L, null, null, null, null)));
        assertTrue(e.getMessage().contains("WalletDeployed.deployWithWallet"), e.getMessage());
        assertEquals(0, f.wallet.createdActions().size(), "the wallet must not be asked for coins");
        assertNull(c.currentUtxo());

        // Acknowledged: proceeds.
        c.deployWithWallet(f.wp,
            new DeployWithWalletOptions(1_000L, null, null, null, List.of("verifySP1FRI")));
        assertEquals(1, f.wallet.createdActions().size());
    }

    @Test
    void deployWithWalletRefusesAnOversizedScriptBeforeTheWallet() {
        Fixture f = new Fixture();
        String huge = "00".repeat(InputLimits.MAX_SCRIPT_BYTES + 1);
        RunarContract c = new RunarContract(artifact(huge), List.of());
        assertThrows(ScriptSizeExceededError.class, () -> c.deployWithWallet(f.wp, null));
        assertEquals(0, f.wallet.createdActions().size());
    }

    @Test
    void deployWithWalletPropagatesCreateActionFailureAndTracksNothing() {
        Fixture f = new Fixture();
        f.wallet.failCreateAction(new IllegalStateException("wallet unavailable"));
        RunarContract c = new RunarContract(artifact("51"), List.of());
        RuntimeException e = assertThrows(RuntimeException.class, () -> c.deployWithWallet(f.wp, null));
        assertTrue(e.getMessage().contains("wallet unavailable"), e.getMessage());
        assertNull(c.currentUtxo());
    }

    @Test
    void deployWithWalletRequiresAWalletProvider() {
        RunarContract c = new RunarContract(artifact("51"), List.of());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> c.deployWithWallet(null, null));
        assertTrue(e.getMessage().contains("WalletProvider"), e.getMessage());
    }
}
