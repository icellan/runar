module PostQuantumSLHDSA {
    use runar::types::{ByteString};
    use runar::crypto::{verifySlhdsaSha2128s};

    struct PostQuantumSLHDSA {
        pubkey: ByteString,
    }

    public fun spend(contract: &PostQuantumSLHDSA, msg: ByteString, sig: ByteString) {
        assert!(verifySlhdsaSha2128s(msg, sig, contract.pubkey), 0);
    }
}
