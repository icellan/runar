package runar.examples.covenantvault;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Addr;
import runar.lang.types.Bigint;
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
        CovenantVault c = new CovenantVault(OWNER, RECIPIENT, Bigint.of(1000));
        ContractSimulator sim = ContractSimulator.stateless(c);
        SigHashPreimage preimage = SigHashPreimage.fromHex("");
        sim.call("spend", SIG, preimage);
    }
}
