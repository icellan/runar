package runar.examples.tokenft;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * FungibleToken -- a UTXO-based fungible token demonstrating the Rúnar
 * multi-output ({@code addOutput}) facility.
 *
 * <p>Ports {@code examples/go/token-ft/FungibleTokenExample.runar.go}
 * to Java. The merge path is omitted here because it relies on
 * {@code txPreimage} introspection which is exercised separately in the
 * covenant-vault / auction ports -- the core transfer / send paths are
 * enough to demonstrate multi-output emission with Bigint-wrapper
 * arithmetic.
 */
class FungibleToken extends StatefulSmartContract {

    PubKey owner;                           // Current owner, mutable
    Bigint balance;                         // Primary token balance, mutable
    @Readonly ByteString tokenId;           // Unique identifier, immutable

    FungibleToken(PubKey owner, Bigint balance, ByteString tokenId) {
        super(owner, balance, tokenId);
        this.owner = owner;
        this.balance = balance;
        this.tokenId = tokenId;
    }

    /**
     * Send {@code amount} tokens to {@code to}. If the full balance is
     * sent, emits one output; otherwise emits two (recipient + change
     * back to the sender).
     */
    @Public
    void transfer(Sig sig, PubKey to, Bigint amount, Bigint outputSatoshis) {
        assertThat(checkSig(sig, this.owner));
        assertThat(outputSatoshis.ge(Bigint.ONE));
        assertThat(amount.gt(Bigint.ZERO));
        assertThat(amount.le(this.balance));

        // First output: recipient receives `amount` tokens
        this.addOutput(outputSatoshis, to, amount);
        // Second output: sender keeps the remaining balance as change (skip if fully spent)
        if (amount.lt(this.balance)) {
            this.addOutput(outputSatoshis, this.owner, this.balance.minus(amount));
        }
    }

    /**
     * Transfer the entire balance to a new owner in a single output.
     */
    @Public
    void send(Sig sig, PubKey to, Bigint outputSatoshis) {
        assertThat(checkSig(sig, this.owner));
        assertThat(outputSatoshis.ge(Bigint.ONE));
        this.addOutput(outputSatoshis, to, this.balance);
    }
}
