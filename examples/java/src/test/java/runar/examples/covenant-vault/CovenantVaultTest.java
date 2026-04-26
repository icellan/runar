package runar.examples.covenantvault;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.types.Addr;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import runar.lang.types.SigHashPreimage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CovenantVaultTest {

    private static final PubKey OWNER = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final Addr   RECIPIENT = Addr.fromHex("0102030405060708090a0b0c0d0e0f1011121314");
    private static final Sig    SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

    @Test
    void contractInstantiates() {
        CovenantVault c = new CovenantVault(OWNER, RECIPIENT, Bigint.of(1000));
        assertNotNull(c);
        assertEquals(OWNER, c.owner);
        assertEquals(RECIPIENT, c.recipient);
        assertEquals(Bigint.of(1000), c.minAmount);
    }

    @Test
    void spendSucceedsWithOwnerSignature() {
        Bigint minAmount = Bigint.of(1000);
        CovenantVault c = new CovenantVault(OWNER, RECIPIENT, minAmount);
        ContractSimulator sim = ContractSimulator.stateless(c);

        // Construct the same expected output the contract builds on-chain so
        // {@code hash256(expectedOutput) === extractOutputHash(preimage)}
        // round-trips. Mirrors the canonical TS test setup: pass the
        // expected outputs hash as the preimage's leading 32 bytes — the
        // simulator's {@link Builtins#extractOutputHash(SigHashPreimage)}
        // returns the first 32 bytes of the preimage parameter directly.
        ByteString p2pkhScript = MockCrypto.cat(
            MockCrypto.cat(ByteString.fromHex("1976a914"), RECIPIENT),
            ByteString.fromHex("88ac")
        );
        ByteString expectedOutput = MockCrypto.cat(
            MockCrypto.num2bin(minAmount.value(), java.math.BigInteger.valueOf(8)),
            p2pkhScript
        );
        ByteString outputsHash = MockCrypto.hash256(expectedOutput);
        SigHashPreimage preimage = new SigHashPreimage(outputsHash.toByteArray());

        sim.call("spend", SIG, preimage);
    }
}
