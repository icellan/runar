pragma runar ^0.1.0;

/// @title BSV21Token -- Pay-to-Public-Key-Hash lock for a BSV-21 fungible token.
/// @notice BSV-21 (v2) is an improvement over BSV-20 that uses ID-based tokens
/// instead of tick-based. The token ID is derived from the deploy transaction
/// (`<txid>_<vout>`), eliminating ticker squatting and enabling admin-controlled
/// distribution.
///
/// BSV-21 Token Lifecycle:
///   1. Deploy+Mint -- A single inscription deploys the token and mints the
///                     initial supply atomically. The token ID is the outpoint
///                     of the output containing this inscription.
///   2. Transfer    -- Inscribe a transfer JSON referencing the token ID and
///                     amount.
///
/// The SDK helpers `BSV21.deployMint()` and `BSV21.transfer()` build the correct
/// inscription payloads for each operation.
contract BSV21Token is SmartContract {
    Addr immutable pubKeyHash;

    constructor(Addr _pubKeyHash) {
        pubKeyHash = _pubKeyHash;
    }

    /// @notice Unlock by proving ownership of the private key corresponding to pubKeyHash.
    function unlock(Sig sig, PubKey pubKey) public {
        require(hash160(pubKey) == pubKeyHash);
        require(checkSig(sig, pubKey));
    }
}
