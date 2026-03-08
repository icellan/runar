pragma runar ^0.1.0;

/// @title Escrow
/// @notice Three-party escrow contract for marketplace payment protection.
/// @dev Holds funds in a UTXO until the buyer, seller, or arbiter authorizes
/// release. The buyer deposits funds by sending to this contract's locking
/// script. Four spending paths allow either party to move funds depending on
/// the transaction outcome:
///
///   - releaseBySeller  — seller confirms delivery, releases funds to themselves.
///   - releaseByArbiter — arbiter resolves a dispute in the seller's favor.
///   - refundToBuyer    — buyer cancels before delivery (self-authorized).
///   - refundByArbiter  — arbiter resolves a dispute in the buyer's favor.
///
/// This is a stateless contract (SmartContract). The three public keys are
/// immutable constructor parameters baked into the locking script at deploy time.
///
/// Script layout:
///   Unlocking: <methodIndex> <sig>
///   Locking:   OP_IF <release paths> OP_ELSE <refund paths> OP_ENDIF
///
/// Each public function becomes an OP_IF branch selected by the method index in
/// the unlocking script.
///
/// Design note: Each path requires only one signature. A production escrow might
/// use 2-of-3 multisig for stronger guarantees, but this contract demonstrates
/// the multi-method spending pattern clearly.
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

    /// @notice Seller confirms delivery and releases the escrowed funds.
    /// @param sig Seller's signature (~72 bytes)
    function releaseBySeller(Sig sig) public {
        require(checkSig(sig, this.seller));
    }

    /// @notice Arbiter resolves a dispute in the seller's favor, releasing funds.
    /// @param sig Arbiter's signature (~72 bytes)
    function releaseByArbiter(Sig sig) public {
        require(checkSig(sig, this.arbiter));
    }

    /// @notice Buyer cancels the transaction before delivery and reclaims funds.
    /// @param sig Buyer's signature (~72 bytes)
    function refundToBuyer(Sig sig) public {
        require(checkSig(sig, this.buyer));
    }

    /// @notice Arbiter resolves a dispute in the buyer's favor, refunding funds.
    /// @param sig Arbiter's signature (~72 bytes)
    function refundByArbiter(Sig sig) public {
        require(checkSig(sig, this.arbiter));
    }
}
