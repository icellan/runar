package runar.conformance.statedigestlog;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.Ripemd160;

import static runar.lang.Builtins.assertThat;

/**
 * DigestLog -- F-352 second witness for the mutable-state shape {Ripemd160}.
 */
class DigestLog extends StatefulSmartContract {

    Ripemd160 digest;

    DigestLog(Ripemd160 digest) {
        super(digest);
        this.digest = digest;
    }

    @Public
    void replace(Ripemd160 newDigest, Bigint version) {
        assertThat(version.gt(Bigint.ZERO));
        this.digest = newDigest;
    }
}
