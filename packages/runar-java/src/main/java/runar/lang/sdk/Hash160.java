package runar.lang.sdk;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;

/** {@code RIPEMD160(SHA256(x))} helper used by P2PKH and Base58Check. */
final class Hash160 {
    private Hash160() {}

    static byte[] hash160(byte[] data) {
        return ripemd160(sha256(data));
    }

    static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] doubleSha256(byte[] data) {
        return sha256(sha256(data));
    }

    static byte[] ripemd160(byte[] data) {
        RIPEMD160Digest d = new RIPEMD160Digest();
        d.update(data, 0, data.length);
        byte[] out = new byte[20];
        d.doFinal(out, 0);
        return out;
    }
}
