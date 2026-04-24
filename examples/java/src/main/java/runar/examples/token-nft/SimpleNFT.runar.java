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
 * <p>Unlike fungible tokens, an NFT is indivisible: the token IS the
 * UTXO. This contract demonstrates ownership transfer and burn via
 * {@code addOutput} (for state continuation) or nothing (for destruction).
 *
 * <p>Ports {@code examples/go/token-nft/NFTExample.runar.go} to Java.
 * Uses the {@link Bigint} wrapper for {@code outputSatoshis} so the
 * comparison {@code outputSatoshis.ge(Bigint.ONE)} lowers to the
 * canonical {@code BinaryExpr(GE)} AST.
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
