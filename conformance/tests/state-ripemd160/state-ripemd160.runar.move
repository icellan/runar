module HashRegistry {
    use runar::StatefulSmartContract;

    resource struct HashRegistry {
        current_hash: &mut Ripemd160,
    }

    public fun update(contract: &mut HashRegistry, new_hash: Ripemd160) {
        contract.current_hash = new_hash;
        assert!(true, 0);
    }
}
