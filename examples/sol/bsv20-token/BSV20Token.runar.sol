pragma runar ^0.1.0;

/// @title BSV20Token -- Pay-to-Public-Key-Hash lock for a BSV-20 fungible token.
/// @notice BSV-20 is a 1sat ordinals token standard where fungible tokens are
/// represented as inscriptions on P2PKH UTXOs. The contract logic is standard
/// P2PKH -- the token semantics (deploy, mint, transfer) are encoded in the
/// inscription envelope and interpreted by indexers, not by the script itself.
///
/// BSV-20 Token Lifecycle:
///   1. Deploy   -- Inscribe `{"p":"bsv-20","op":"deploy","tick":"RUNAR","max":"21000000"}`
///                  onto a UTXO to register a new ticker. First deployer wins.
///   2. Mint     -- Inscribe `{"p":"bsv-20","op":"mint","tick":"RUNAR","amt":"1000"}`
///                  to claim tokens up to the per-mint limit.
///   3. Transfer -- Inscribe `{"p":"bsv-20","op":"transfer","tick":"RUNAR","amt":"50"}`
///                  to move tokens between addresses.
///
/// The SDK helpers `BSV20.deploy()`, `BSV20.mint()`, and `BSV20.transfer()`
/// build the correct inscription payloads for each operation.
contract BSV20Token is SmartContract {
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
