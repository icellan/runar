package runar.examples.tokennft;

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
 * SimpleNFT -- a non-fungible token (NFT) represented as a single UTXO.
 *
 * <p>Ports {@code examples/python/token-nft/NFTExample.runar.py} to Java.
 * Unlike fungible tokens, an NFT is indivisible -- the token IS the UTXO.
 * Demonstrates ownership transfer and burn (permanent destruction) of a
 * unique digital asset, enforced entirely by Bitcoin Script.
 *
 * <h2>UTXO as NFT</h2>
 * <p>Each NFT is a single UTXO carrying:
 * <ul>
 *   <li>{@code owner} (mutable): current owner's public key, updated on
 *       transfer.</li>
 *   <li>{@code tokenId} (readonly): unique identifier baked into the
 *       locking script.</li>
 *   <li>{@code metadata} (readonly): content hash or URI, also baked in
 *       and immutable.</li>
 * </ul>
 *
 * <h2>Operations</h2>
 * <ul>
 *   <li>{@code transfer} -- changes ownership; emits one continuation
 *       UTXO via {@code addOutput}.</li>
 *   <li>{@code burn} -- destroys the token permanently. No
 *       {@code addOutput} = no successor = token ceases to exist.</li>
 * </ul>
 *
 * <p>Authorization: both operations require the current owner's ECDSA
 * signature via {@code checkSig}.
 */
class SimpleNFT extends StatefulSmartContract {

    PubKey owner;                           // Current owner, mutable
    @Readonly ByteString tokenId;           // Unique identifier, immutable
    @Readonly ByteString metadata;          // Content hash / URI, immutable

    SimpleNFT(PubKey owner, ByteString tokenId, ByteString metadata) {
        super(owner, tokenId, metadata);
        this.owner = owner;
        this.tokenId = tokenId;
        this.metadata = metadata;
    }

    /** Transfer ownership of the NFT to a new owner. */
    @Public
    void transfer(Sig sig, PubKey newOwner, Bigint outputSatoshis) {
        assertThat(checkSig(sig, this.owner));
        assertThat(outputSatoshis.ge(Bigint.ONE));
        this.addOutput(outputSatoshis, newOwner);
    }

    /**
     * Permanently destroy the NFT. Because this method does not call
     * {@code addOutput} and does not mutate state, the compiler generates
     * no state continuation -- the UTXO is spent with no successor.
     */
    @Public
    void burn(Sig sig) {
        assertThat(checkSig(sig, this.owner));
    }
}
