package runar.examples.statefulwotsgate;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.verifyWOTS;

// StatefulWOTSGate — stateful + post-quantum interaction fixture (GAP-407).
// TEST FIXTURE, NOT AN AUTHORIZATION GATE: wotsPubKey is a spender-supplied witness,
// so anyone can advance the counter; it exists to exercise stateful covenant +
// WOTS+ verify composition (GAP-407).
class StatefulWOTSGate extends StatefulSmartContract {
    Bigint count;

    StatefulWOTSGate(Bigint count) {
        super(count);
        this.count = count;
    }

    @Public
    void advance(ByteString msg, ByteString sig, ByteString wotsPubKey) {
        assertThat(verifyWOTS(msg, sig, wotsPubKey));
        this.count = this.count.plus(Bigint.ONE);
    }
}
