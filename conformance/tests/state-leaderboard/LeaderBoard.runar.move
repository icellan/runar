// LeaderBoard -- F-352 second witness for the mutable-state shape
// {PubKey, bigint}.
module LeaderBoard {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig};

    resource struct LeaderBoard {
        leader: &mut PubKey,
        top_score: &mut bigint,
    }

    public fun claim(contract: &mut LeaderBoard, sig: Sig, new_leader: PubKey, score: bigint) {
        assert!(check_sig(sig, contract.leader), 0);
        assert!(score > contract.top_score, 0);
        contract.leader = new_leader;
        contract.top_score = score;
    }
}
