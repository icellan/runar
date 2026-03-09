pragma runar ^0.1.0;

/// @title Escrow
/// @notice Three-party escrow contract for marketplace payment protection.
/// @dev Holds funds in a UTXO until two parties jointly authorize a spend.
/// The buyer deposits funds by sending to this contract's locking script.
/// Two spending paths allow funds to move depending on the transaction outcome:
///
///   - release — seller + arbiter both sign to release funds to the seller
///     (e.g., goods delivered successfully).
///   - refund  — buyer + arbiter both sign to refund funds to the buyer
///     (e.g., dispute resolved in buyer's favor).
///
/// The arbiter serves as the trust anchor — no single party can act alone.
/// Both paths require two signatures (dual-sig), ensuring the arbiter must
/// co-sign every spend. This prevents unilateral action by either party.
///
/// Script layout:
///   Unlocking: <methodIndex> <sig1> <sig2>
///   Locking:   OP_IF <seller checkSig> <arbiter checkSig>
///              OP_ELSE <buyer checkSig> <arbiter checkSig> OP_ENDIF
contract Escrow is SmartContract {
    /// @notice Buyer's compressed public key (33 bytes).
    PubKey immutable buyer;
    /// @notice Seller's compressed public key (33 bytes).
    PubKey immutable seller;
    /// @notice Arbiter's compressed public key (33 bytes).
    PubKey immutable arbiter;

    /// @param _buyer   Buyer's compressed public key (33 bytes)
    /// @param _seller  Seller's compressed public key (33 bytes)
    /// @param _arbiter Arbiter's compressed public key (33 bytes)
    constructor(PubKey _buyer, PubKey _seller, PubKey _arbiter) {
        buyer = _buyer;
        seller = _seller;
        arbiter = _arbiter;
    }

    /// @notice Release escrowed funds to the seller.
    /// @param sellerSig Seller's signature
    /// @param arbiterSig Arbiter's signature
    function release(Sig sellerSig, Sig arbiterSig) public {
        require(checkSig(sellerSig, this.seller));
        require(checkSig(arbiterSig, this.arbiter));
    }

    /// @notice Refund escrowed funds to the buyer.
    /// @param buyerSig Buyer's signature
    /// @param arbiterSig Arbiter's signature
    function refund(Sig buyerSig, Sig arbiterSig) public {
        require(checkSig(buyerSig, this.buyer));
        require(checkSig(arbiterSig, this.arbiter));
    }
}
