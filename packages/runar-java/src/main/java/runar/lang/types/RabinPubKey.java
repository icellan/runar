package runar.lang.types;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Rabin public key — the large integer modulus ({@code N = p * q}) used
 * by the Rabin verification circuit. Baked into the locking script as a
 * readonly property of the consuming contract.
 */
public final class RabinPubKey {

    private final BigInteger value;

    public RabinPubKey(BigInteger value) {
        this.value = Objects.requireNonNull(value, "value");
    }

    public BigInteger value() {
        return value;
    }

    public static RabinPubKey fromHex(String hex) {
        if (hex.isEmpty()) return new RabinPubKey(BigInteger.ZERO);
        return new RabinPubKey(new BigInteger(1, HexFormat.of().parseHex(hex)));
    }

    public String toHex() {
        return value.toString(16);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof RabinPubKey that && this.value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return "RabinPubKey(0x" + toHex() + ")";
    }
}
