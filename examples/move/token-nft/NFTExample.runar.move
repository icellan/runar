// SimpleNFT -- A non-fungible token (NFT) represented as a single UTXO.
//
// Unlike fungible tokens, an NFT is indivisible -- the token IS the UTXO. This contract
// demonstrates ownership transfer and burn (permanent destruction) of a unique digital asset,
// enforced entirely by Bitcoin Script.
//
// UTXO as NFT:
// Each NFT is a single UTXO carrying:
//   - owner (mutable): current owner's public key, updated on transfer
//   - token_id (readonly): unique identifier baked into the locking script
//   - metadata (readonly): content hash or URI, also baked in and immutable
//
// Operations:
//   transfer -- Changes ownership. Creates one continuation UTXO via add_output.
//   burn     -- Destroys the token permanently. No add_output = no successor = token ceases to exist.
//
// Authorization: Both operations require the current owner's ECDSA signature via check_sig.
module SimpleNFT {
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig};

    resource struct SimpleNFT {
        owner: &mut PubKey,       // Current owner's public key. Mutable -- updated when the NFT is transferred.
        token_id: ByteString,     // Unique token identifier. Immutable -- baked into the locking script at deploy time.
        metadata: ByteString,     // Token metadata (content hash or URI). Immutable for the token's lifetime.
    }

    // Transfer ownership of the NFT to a new owner.
    //
    // Creates one continuation UTXO via add_output with the new owner. token_id and
    // metadata remain unchanged (readonly properties are baked into the locking script).
    // add_output(satoshis, owner) takes the single mutable property positionally.
    //
    // Parameters:
    //   sig: current owner's signature (authorization)
    //   new_owner: new owner's public key
    //   output_satoshis: satoshis to fund the continuation UTXO
    public fun transfer(contract: &mut SimpleNFT, sig: Sig, new_owner: PubKey, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);
        contract.add_output(output_satoshis, new_owner);
    }

    // Burn (permanently destroy) the NFT.
    //
    // The owner signs to authorize destruction. Because this method does not call add_output
    // and does not mutate state, the compiler generates no state continuation. The UTXO is
    // simply spent with no successor -- the token ceases to exist on-chain.
    //
    // Parameters:
    //   sig: current owner's signature (authorization)
    public fun burn(contract: &mut SimpleNFT, sig: Sig) {
        assert!(check_sig(sig, contract.owner), 0);
    }
}
