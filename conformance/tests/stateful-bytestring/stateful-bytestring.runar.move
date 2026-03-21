module MessageBoard {
    use runar::StatefulSmartContract;

    resource struct MessageBoard {
        message: &mut ByteString,
        owner: PubKey,
    }

    public fun post(contract: &mut MessageBoard, new_message: ByteString) {
        contract.message = new_message;
        assert!(true, 0);
    }

    public fun burn(contract: &mut MessageBoard, sig: Sig) {
        assert!(check_sig(sig, contract.owner), 0);
    }
}
