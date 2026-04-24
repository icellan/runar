package runar.lang.types;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Rabin signature — a large unsigned integer modulo the signer's Rabin
 * public key. Verification (see {@code verifyRabinSig} in
 * {@link runar.lang.Builtins}) is cheap in Bitcoin Script because it
 * reduces to modular multiplication + comparison, making Rabin a natural
 * fit for on-chain oracle feeds.
 */
public final class RabinSig {

    private final BigInteger value;

    public RabinSig(BigInteger value) {
        this.value = Objects.requireNonNull(value, "value");
    }

    public BigInteger value() {
        return value;
    }

    public static RabinSig fromHex(String hex) {
        if (hex.isEmpty()) return new RabinSig(BigInteger.ZERO);
        return new RabinSig(new BigInteger(1, HexFormat.of().parseHex(hex)));
    }

    public String toHex() {
        return value.toString(16);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof RabinSig that && this.value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return "RabinSig(0x" + toHex() + ")";
    }
}
