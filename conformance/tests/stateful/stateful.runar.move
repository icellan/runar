module Stateful {
    use runar::types::{Int, SigHashPreimage};
    use runar::crypto::{check_preimage, hash256};
    use runar::tx::{extract_output_hash, get_state_script};

    resource struct Stateful {
        count: &mut Int,
        max_count: Int,
    }

    public fun increment(contract: &mut Stateful, amount: Int, tx_preimage: SigHashPreimage) {
        assert!(check_preimage(tx_preimage), 0);
        contract.count = contract.count + amount;
        assert!(contract.count <= contract.max_count, 0);
        assert_eq!(hash256(get_state_script(contract)), extract_output_hash(tx_preimage));
    }

    public fun reset(contract: &mut Stateful, tx_preimage: SigHashPreimage) {
        assert!(check_preimage(tx_preimage), 0);
        contract.count = 0;
        assert_eq!(hash256(get_state_script(contract)), extract_output_hash(tx_preimage));
    }
}
