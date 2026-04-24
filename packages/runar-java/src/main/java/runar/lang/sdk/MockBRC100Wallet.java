package runar.lang.sdk;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Test double for {@link BRC100Wallet}. Wraps one {@link LocalSigner}
 * per derivation path so tests can drive the {@link WalletProvider}
 * through a realistic multi-signer flow without a live wallet.
 *
 * <p>Production code should never use this class — it holds unsealed
 * private keys in process. It exists to mirror the Go SDK's
 * {@code MockWalletClient} used by {@code sdk_wallet_test.go}.
 */
public final class MockBRC100Wallet implements BRC100Wallet {

    private final Map<String, LocalSigner> signers = new LinkedHashMap<>();
    private final Map<String, Integer> signCounts = new HashMap<>();

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
