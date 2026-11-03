use runar::prelude::*;

/// LeaderBoard -- F-352 second witness for the mutable-state shape
/// {PubKey, bigint}.
#[runar::contract]
pub struct LeaderBoard {
    pub leader: PubKey,
    pub top_score: Bigint,
}

impl LeaderBoard {
    pub fn claim(&mut self, sig: &Sig, new_leader: PubKey, score: Bigint) {
        assert!(check_sig(sig, &self.leader));
        assert!(score > self.top_score);
        self.leader = new_leader;
        self.top_score = score;
    }
}
