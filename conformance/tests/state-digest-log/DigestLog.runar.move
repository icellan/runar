// DigestLog -- F-352 second witness for the mutable-state shape {Ripemd160}.
module DigestLog {
    use runar::StatefulSmartContract;

    resource struct DigestLog {
        digest: &mut Ripemd160,
    }

    public fun replace(contract: &mut DigestLog, new_digest: Ripemd160, version: bigint) {
        assert!(version > 0, 0);
        contract.digest = new_digest;
    }
}
