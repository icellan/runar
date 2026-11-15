package runar.lang.sdk;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Test double for {@link BRC100Wallet}. Wraps one {@link LocalSigner}
 * per derivation path so tests can drive the {@link WalletProvider}
 * through a realistic multi-signer flow without a live wallet.
 *
 * <p>Production code should never use this class — it holds unsealed
 * private keys in process. It exists to mirror the Go SDK's
 * {@code MockWalletClient} used by {@code sdk_wallet_test.go}.
 *
 * <p>Action surface: {@link #createAction} records the action, assigns a
 * deterministic txid, and adds every output it creates to the wallet's own
 * output store, so a later {@link #listOutputs} sees it (no transaction is
 * built — {@link WalletActionResult#rawTx()} is {@code null}). Seed outputs with
 * {@link #addOutput}; make {@code createAction} fail with
 * {@link #failCreateAction}.
 */
public final class MockBRC100Wallet implements BRC100Wallet {

    private final Map<String, LocalSigner> signers = new LinkedHashMap<>();
    private final Map<String, Integer> signCounts = new HashMap<>();

    /** One recorded {@code createAction} call. */
    public record Action(String description, List<WalletActionOutput> outputs) {}

    /** One recorded {@code listOutputs} call. */
    public record ListCall(String basket, List<String> tags, int limit) {}

    private record Held(String basket, List<String> tags, WalletOutput output) {}

    private final List<Held> outputs = new ArrayList<>();
    private final List<Action> actions = new ArrayList<>();
    private final List<ListCall> listCalls = new ArrayList<>();
    private RuntimeException createActionFailure;

    /** Registers a {@link LocalSigner} under a derivation path. */
    public MockBRC100Wallet register(String derivationPath, LocalSigner signer) {
        if (derivationPath == null || derivationPath.isEmpty()) {
            throw new IllegalArgumentException("MockBRC100Wallet.register: derivationPath is required");
        }
        if (signer == null) {
            throw new IllegalArgumentException("MockBRC100Wallet.register: signer is required");
        }
        signers.put(derivationPath, signer);
        return this;
    }

    /** Registers a fresh random key under the given path (tests only). */
    public MockBRC100Wallet registerRandom(String derivationPath) {
        return register(derivationPath, LocalSigner.random(new java.security.SecureRandom()));
    }

    /** Read-only view of the derivation-paths known to this wallet. */
    public Map<String, LocalSigner> signers() {
        return Collections.unmodifiableMap(signers);
    }

    /** Count of {@link #sign} calls per path (for test assertions). */
    public int signCount(String derivationPath) {
        return signCounts.getOrDefault(derivationPath, 0);
    }

    @Override
    public byte[] sign(byte[] sighash, String derivationPath) {
        LocalSigner s = resolve(derivationPath, "sign");
        signCounts.merge(derivationPath, 1, Integer::sum);
        return s.sign(sighash, null);
    }

    @Override
    public byte[] pubKey(String derivationPath) {
        return resolve(derivationPath, "pubKey").pubKey();
    }

    @Override
    public String address(String derivationPath) {
        return resolve(derivationPath, "address").address();
    }

    /** Seeds an output the wallet holds in {@code basket} under {@code tags}. */
    public synchronized MockBRC100Wallet addOutput(String basket, List<String> tags, WalletOutput output) {
        outputs.add(new Held(basket, tags == null ? List.of() : List.copyOf(tags), output));
        return this;
    }

    /** Makes every later {@link #createAction} throw {@code failure}. */
    public synchronized MockBRC100Wallet failCreateAction(RuntimeException failure) {
        this.createActionFailure = failure;
        return this;
    }

    /** Every {@link #createAction} call so far, in order. */
    public synchronized List<Action> createdActions() {
        return List.copyOf(actions);
    }

    /** Every {@link #listOutputs} call so far, in order. */
    public synchronized List<ListCall> listCalls() {
        return List.copyOf(listCalls);
    }

    @Override
    public synchronized WalletActionResult createAction(String description, List<WalletActionOutput> outs) {
        if (createActionFailure != null) {
            throw createActionFailure;
        }
        List<WalletActionOutput> copy = outs == null ? List.of() : List.copyOf(outs);
        actions.add(new Action(description, copy));
        String txid = HexFormat.of().formatHex(Hash160.sha256(
            ("mock-wallet-action-" + actions.size()).getBytes(StandardCharsets.UTF_8)));
        for (int i = 0; i < copy.size(); i++) {
            WalletActionOutput o = copy.get(i);
            outputs.add(new Held(o.basket(), o.tags(),
                new WalletOutput(o.satoshis(), o.lockingScript(), true, txid + "." + i)));
        }
        return new WalletActionResult(txid, null);
    }

    @Override
    public synchronized List<WalletOutput> listOutputs(String basket, List<String> tags, int limit) {
        List<String> want = tags == null ? List.of() : List.copyOf(tags);
        listCalls.add(new ListCall(basket, want, limit));
        List<WalletOutput> out = new ArrayList<>();
        for (Held h : outputs) {
            if (out.size() >= limit) break;
            if (!java.util.Objects.equals(h.basket(), basket)) continue;
            // BRC-100 default tagQueryMode "any".
            if (!want.isEmpty() && want.stream().noneMatch(h.tags()::contains)) continue;
            out.add(h.output());
        }
        return out;
    }

    private LocalSigner resolve(String derivationPath, String op) {
        LocalSigner s = signers.get(derivationPath);
        if (s == null) {
            throw new IllegalArgumentException(
                "MockBRC100Wallet." + op + ": no signer registered at derivation path '"
                    + derivationPath + "'"
            );
        }
        return s;
    }
}
