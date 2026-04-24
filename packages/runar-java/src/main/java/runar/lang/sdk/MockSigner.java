package runar.lang.sdk;

import java.util.HexFormat;

/**
 * Deterministic non-cryptographic {@link Signer} for tests. Matches
 * the Go SDK's {@code MockSignerImpl}: returns a fixed 72-byte
 * DER-shaped placeholder (0x30 + 70 zero bytes + 0x41 sighash flag),
 * a 33-byte compressed pubkey of 0x02 followed by 32 zero bytes, and
 * a mock 40-char hex address.
 */
public final class MockSigner implements Signer {

    private static final HexFormat HEX = HexFormat.of();

    public static final byte[] DEFAULT_PUBKEY =
        HEX.parseHex("02" + "0".repeat(64));

    public static final String DEFAULT_ADDRESS = "0".repeat(40);

    /** 72-byte mock signature: 0x30 || 70 zero bytes || 0x41. */
    public static final byte[] DEFAULT_SIGNATURE;
    static {
        byte[] b = new byte[72];
        b[0] = 0x30;
        b[71] = 0x41;
        DEFAULT_SIGNATURE = b;
    }

    private final byte[] pubKey;
    private final String address;

    public MockSigner() {
        this(DEFAULT_PUBKEY.clone(), DEFAULT_ADDRESS);
    }

    public MockSigner(byte[] pubKey, String address) {
        this.pubKey = pubKey.clone();
        this.address = address;
    }

    @Override
    public byte[] sign(byte[] sighash, String derivationKey) {
        // Return a 71-byte (DER-ish) placeholder *without* the sighash
        // flag byte; the caller appends the flag when building the
        // unlocking script, matching the LocalSigner contract.
        byte[] b = new byte[71];
        b[0] = 0x30;
        return b;
    }

    @Override
    public byte[] pubKey() {
        return pubKey.clone();
    }

    @Override
    public String address() {
        return address;
    }
}
