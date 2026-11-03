pragma runar ^0.1.0;

/// @title LeaderBoard
/// @notice F-352 second witness for the mutable-state shape {PubKey, bigint}.
contract LeaderBoard is StatefulSmartContract {
    PubKey leader;
    bigint topScore;

    constructor(PubKey _leader, bigint _topScore) {
        leader = _leader;
        topScore = _topScore;
    }

    function claim(Sig sig, PubKey newLeader, bigint score) public {
        require(checkSig(sig, this.leader));
        require(score > this.topScore);
        this.leader = newLeader;
        this.topScore = score;
    }
}
