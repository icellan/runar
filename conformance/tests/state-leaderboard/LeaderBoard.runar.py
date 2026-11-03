from runar import (
    StatefulSmartContract, PubKey, Sig, Bigint,
    public, assert_, check_sig,
)


class LeaderBoard(StatefulSmartContract):
    """LeaderBoard -- F-352 second witness for the mutable-state shape
    {PubKey, bigint}."""

    leader: PubKey
    top_score: Bigint

    def __init__(self, leader: PubKey, top_score: Bigint):
        super().__init__(leader, top_score)
        self.leader = leader
        self.top_score = top_score

    @public
    def claim(self, sig: Sig, new_leader: PubKey, score: Bigint):
        assert_(check_sig(sig, self.leader))
        assert_(score > self.top_score)
        self.leader = new_leader
        self.top_score = score
