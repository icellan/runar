package runar.integration.helpers;

import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicLong;

import runar.lang.sdk.LocalSigner;
import runar.lang.sdk.Signer;

/**
 * Deterministic funded wallet for integration tests. Parity with the
 * Python {@code create_funded_wallet} and Go {@code helpers.NewWallet}
 * helpers.
 *
 * <p>Each call to {@link #create} advances a process-local counter,
 * giving every test its own key and UTXO so parallel tests never
 * compete for the same funds. The index is seeded from the PID of the
 * current JVM to keep parallel Gradle workers from colliding.
 */
public final class IntegrationWallet {

    private static final AtomicLong COUNTER = new AtomicLong(
        // mirror Python: pid * 1000 — gives each JVM a disjoint scalar range.
        (long) ProcessHandle.current().pid() * 1000L
    );

    private final String privKeyHex;
    private final LocalSigner signer;
    private final String pubKeyHex;
    private final String pubKeyHash;
    private final String address;

    private IntegrationWallet(String privKeyHex, LocalSigner signer) {
        this.privKeyHex = privKeyHex;
        this.signer = signer;
        byte[] pub = signer.pubKey();
        this.pubKeyHex = toHex(pub);
        this.pubKeyHash = hash160Hex(pub);
        // Regtest P2PKH uses the testnet version byte 0x6f.
        this.address = regtestP2PKHAddress(pubKeyHash);
    }

    public String privKeyHex() { return privKeyHex; }
    public Signer signer() { return signer; }
    public String pubKeyHex() { return pubKeyHex; }
    public String pubKeyHash() { return pubKeyHash; }
    public String address() { return address; }

    /** Creates a new wallet without funding. */
    public static IntegrationWallet create() {
        long idx = COUNTER.incrementAndGet();
        String hex = String.format("%064x", idx);
        return new IntegrationWallet(hex, new LocalSigner(hex));
    }

    /**
     * Creates a wallet and funds it with {@code btc} BTC by importing
     * the address into the node's wallet (SV Node only) and calling
     * {@code sendtoaddress}. Then mines one block to confirm. On
     * Teranode (no wallet) this method skips the funding step — tests
     * must supply their own coinbase UTXO.
     */
    public static IntegrationWallet createFunded(RpcClient rpc, double btc) {
        IntegrationWallet w = create();
        if (!rpc.isTeranode()) {
            try {
                rpc.call("importaddress", w.address, "", false);
            } catch (Exception ignored) { /* already imported */ }
            rpc.call("sendtoaddress", w.address, Double.valueOf(btc));
            rpc.mine(1);
        }
        return w;
    }

    private static String regtestP2PKHAddress(String pubKeyHashHex) {
        byte[] payload = new byte[21];
        payload[0] = (byte) 0x6f;
        byte[] pkh = fromHex(pubKeyHashHex);
        System.arraycopy(pkh, 0, payload, 1, 20);
        byte[] checksum;
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] a = sha.digest(payload);
            sha.reset();
            byte[] b = sha.digest(a);
            checksum = new byte[4];
            System.arraycopy(b, 0, checksum, 0, 4);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        byte[] full = new byte[payload.length + 4];
        System.arraycopy(payload, 0, full, 0, payload.length);
        System.arraycopy(checksum, 0, full, payload.length, 4);
        return base58Encode(full);
    }

    private static final String B58 =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private static String base58Encode(byte[] data) {
        java.math.BigInteger n = new java.math.BigInteger(1, data);
        StringBuilder sb = new StringBuilder();
        java.math.BigInteger BASE = java.math.BigInteger.valueOf(58);
        while (n.signum() > 0) {
            java.math.BigInteger[] dr = n.divideAndRemainder(BASE);
            sb.append(B58.charAt(dr[1].intValue()));
            n = dr[0];
        }
        for (byte b : data) {
            if (b == 0) sb.append('1');
            else break;
        }
        return sb.reverse().toString();
    }

    private static String hash160Hex(byte[] data) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] a = sha.digest(data);
            // BouncyCastle ripemd160 lives in the SDK's classpath via bcprov.
            org.bouncycastle.crypto.digests.RIPEMD160Digest ripe =
                new org.bouncycastle.crypto.digests.RIPEMD160Digest();
            ripe.update(a, 0, a.length);
            byte[] out = new byte[20];
            ripe.doFinal(out, 0);
            return toHex(out);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    static byte[] fromHex(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }
}
