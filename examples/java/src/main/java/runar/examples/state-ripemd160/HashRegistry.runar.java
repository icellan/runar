package runar.examples.stateripemd160;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Ripemd160;

import static runar.lang.Builtins.assertThat;

/**
 * HashRegistry -- minimal stateful contract that stores a Ripemd160
 * digest and lets anyone replace it. Conformance fixture for the
 * {@code Ripemd160} type round-trip through state continuation.
 */
class HashRegistry extends StatefulSmartContract {

    Ripemd160 currentHash;

    HashRegistry(Ripemd160 currentHash) {
        super(currentHash);
        this.currentHash = currentHash;
    }

    @Public
    void update(Ripemd160 newHash) {
        this.currentHash = newHash;
        assertThat(true);
    }
}
