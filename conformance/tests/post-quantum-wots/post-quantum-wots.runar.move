module PostQuantumWOTS {
    use runar::types::{ByteString};
    use runar::crypto::{verifyWOTS};

    struct PostQuantumWOTS {
        pubkey: ByteString,
    }

    public fun spend(contract: &PostQuantumWOTS, msg: ByteString, sig: ByteString) {
        assert!(verifyWOTS(msg, sig, contract.pubkey), 0);
    }
}
