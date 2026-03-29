module PostQuantumWOTS {
    use runar::types::{ByteString};
    use runar::crypto::{verifyWOTS};

    resource struct PostQuantumWOTS {
        pubkey: ByteString,
    }

    public fun spend(contract: &PostQuantumWOTS, msg: ByteString, sig: ByteString) {
        assert!(verifyWOTS(msg, sig, contract.pubkey), 0);
    }
}
