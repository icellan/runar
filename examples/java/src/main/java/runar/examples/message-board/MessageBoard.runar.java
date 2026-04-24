package runar.examples.messageboard;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * MessageBoard -- a stateful smart contract with a ByteString mutable
 * state field.
 *
 * <p>Demonstrates Rúnar's ByteString state management: a message that
 * persists and can be updated across spending transactions on the
 * Bitcoin SV blockchain.
 *
 * <p>Because this class extends {@link StatefulSmartContract} (not
 * SmartContract), the compiler automatically injects:
 * <ul>
 *   <li>{@code checkPreimage} at each public method entry -- verifies
 *       the spending transaction matches the sighash preimage.</li>
 *   <li>State continuation at each public method exit -- serializes
 *       updated state into the new output script.</li>
 * </ul>
 *
 * <p><strong>Script layout (on-chain):</strong>
 * <pre>
 * Locking: &lt;contract logic&gt; OP_RETURN &lt;message&gt; &lt;owner&gt;
 * </pre>
 * The state ({@code message}) is serialized as push data after
 * OP_RETURN. The {@code owner} is readonly and baked into the locking
 * script. When spent, the compiler-injected preimage check ensures the
 * new output carries the correct updated state.
 *
 * <p><strong>Authorization:</strong> The {@link #post} method has no
 * access control -- anyone can update the message. The {@link #burn}
 * method requires the owner's signature to permanently destroy the
 * contract (no continuation output).
 */
class MessageBoard extends StatefulSmartContract {

    /** The current message. Mutable -- updated via {@link #post}. */
    ByteString message;
    /** The contract owner's public key. Readonly -- baked into the locking script. */
    @Readonly PubKey owner;

    MessageBoard(ByteString message, PubKey owner) {
        super(message, owner);
        this.message = message;
        this.owner = owner;
    }

    /**
     * Post a new message, replacing the current one. Anyone can call
     * this method -- no signature required.
     */
    @Public
    void post(ByteString newMessage) {
        this.message = newMessage;
    }

    /**
     * Burn the contract -- terminal spend with no continuation output.
     * Only the owner can burn the contract (requires a valid signature).
     */
    @Public
    void burn(Sig sig) {
        assertThat(checkSig(sig, this.owner));
    }
}
