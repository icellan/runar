// CovenantVault -- a stateless Bitcoin covenant contract.
//
// A covenant is a self-enforcing spending constraint: the locking script
// dictates not just *who* can spend the funds, but *how* they may be spent.
// This contract demonstrates the pattern by combining three verification
// layers in its single public method:
//
//   1. Owner authorization  -- the owner's ECDSA signature must be valid
//      (proves who is spending).
//   2. Preimage verification -- check_preimage (OP_PUSH_TX) proves the
//      contract is inspecting the real spending transaction, enabling
//      on-chain introspection of its fields.
//   3. Covenant rule -- the contract constructs the expected P2PKH output
//      on-chain (recipient address + min_amount satoshis) and verifies its
//      hash against the transaction's hashOutputs field. This constrains
//      both the destination and the amount at the consensus level.
//
// Script layout (simplified):
//   Unlocking: <opPushTxSig> <sig> <txPreimage>
//   Locking:   <pubKey> OP_CHECKSIG OP_VERIFY <checkPreimage>
//              <buildP2PKH(recipient)> <num2bin(minAmount,8)> OP_CAT
//              OP_HASH256 <extractOutputHash(preimage)> OP_EQUAL OP_VERIFY
//
// Use cases for this pattern include withdrawal limits, time-locked vaults,
// rate-limited spending, and enforced change addresses.
//
// Contract model: Stateless (SmartContract). All fields are readonly and
// baked into the locking script at deploy time.
module CovenantVault {
    use runar::types::{PubKey, Sig, Addr, ByteString, SigHashPreimage};
    use runar::crypto::{check_sig, check_preimage, extract_output_hash, hash256, num2bin, cat};

    // Vault state: all fields are readonly constructor parameters.
    //   owner      -- compressed ECDSA public key (33 bytes).
    //   recipient  -- address hash (20-byte hash160 of the recipient's pubkey).
    //   min_amount -- minimum output satoshis enforced by the covenant.
    struct CovenantVault {
        owner: PubKey,
        recipient: Addr,
        min_amount: bigint,
    }

    // Spend funds held by this covenant.
    //
    // Constructs the expected P2PKH output on-chain and verifies it against
    // the transaction's hashOutputs from the sighash preimage.
    //
    // Parameters:
    //   sig          -- ECDSA signature from the owner (~72 bytes DER).
    //   tx_preimage  -- sighash preimage (variable length) for check_preimage.
    public fun spend(contract: &CovenantVault, sig: Sig, tx_preimage: SigHashPreimage) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(check_preimage(tx_preimage), 0);

        // Construct expected P2PKH output and verify against hashOutputs
        let p2pkh_script: ByteString = cat(cat(0x1976a914, contract.recipient), 0x88ac);
        let expected_output: ByteString = cat(num2bin(contract.min_amount, 8), p2pkh_script);
        assert!(hash256(expected_output) == extract_output_hash(tx_preimage), 0);
    }
}
