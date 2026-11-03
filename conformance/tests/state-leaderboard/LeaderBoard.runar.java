package runar.conformance.stateleaderboard;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;

/**
 * LeaderBoard -- F-352 second witness for the mutable-state shape
 * {PubKey, bigint}.
 */
class LeaderBoard extends StatefulSmartContract {

    PubKey leader;
    Bigint topScore;

    LeaderBoard(PubKey leader, Bigint topScore) {
        super(leader, topScore);
        this.leader = leader;
        this.topScore = topScore;
    }

    @Public
    void claim(Sig sig, PubKey newLeader, Bigint score) {
        assertThat(checkSig(sig, this.leader));
        assertThat(score.gt(this.topScore));
        this.leader = newLeader;
        this.topScore = score;
    }
}
