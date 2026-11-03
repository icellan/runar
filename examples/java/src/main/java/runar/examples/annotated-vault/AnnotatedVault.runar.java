package runar.examples.annotatedvault;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * AnnotatedVault -- N-044 conformance fixture: a mutable variable-length
 * ByteString state field ({@code memo}) BEFORE a mutable PubKey
 * ({@code owner}). Anyone may replace the memo; only the owner may withdraw.
 */
class AnnotatedVault extends StatefulSmartContract {

    ByteString memo;
    PubKey owner;
    Bigint balance;

    AnnotatedVault(ByteString memo, PubKey owner, Bigint balance) {
        super(memo, owner, balance);
        this.memo = memo;
        this.owner = owner;
        this.balance = balance;
    }

    /** Replace the memo. Anyone can call. */
    @Public
    void annotate(ByteString nextMemo) {
        this.memo = nextMemo;
    }

    /** Only the owner may spend. */
    @Public
    void withdraw(Sig sig) {
        assertThat(checkSig(sig, this.owner));
    }
}
