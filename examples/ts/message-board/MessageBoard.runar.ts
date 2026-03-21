import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

/**
 * MessageBoard -- a stateful smart contract with a ByteString mutable state field.
 *
 * Demonstrates Runar's ByteString state management: a message that persists
 * and can be updated across spending transactions on the Bitcoin SV blockchain.
 *
 * Because this class extends {@link StatefulSmartContract} (not SmartContract),
 * the compiler automatically injects:
 *   - `checkPreimage` at each public method entry -- verifies the spending
 *     transaction matches the sighash preimage.
 *   - State continuation at each public method exit -- serializes updated
 *     state into the new output script.
 *
 * **Script layout (on-chain):**
 * ```
 * Locking: <contract logic> OP_RETURN <message> <owner>
 * ```
 * The state (`message`) is serialized as push data after OP_RETURN. The
 * `owner` is readonly and baked into the locking script. When spent,
 * the compiler-injected preimage check ensures the new output carries the
 * correct updated state.
 *
 * **Authorization:** The `post` method has no access control -- anyone can
 * update the message. The `burn` method requires the owner's signature to
 * permanently destroy the contract (no continuation output).
 *
 * @param message - The current message stored on-chain (mutable ByteString)
 * @param owner   - The contract owner's compressed public key (readonly)
 */
class MessageBoard extends StatefulSmartContract {
  /** The current message. Mutable -- updated via `post`. */
  message: ByteString;
  /** The contract owner's public key. Readonly -- baked into the locking script. */
  readonly owner: PubKey;

  constructor(message: ByteString, owner: PubKey) {
    super(message, owner);
    this.message = message;
    this.owner = owner;
  }

  /**
   * Post a new message, replacing the current one.
   * Anyone can call this method -- no signature required.
   */
  public post(newMessage: ByteString) {
    this.message = newMessage;
  }

  /**
   * Burn the contract -- terminal spend with no continuation output.
   * Only the owner can burn the contract (requires a valid signature).
   */
  public burn(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }
}
