import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

/**
 * LeaderBoard -- F-352 second witness for the mutable-state shape
 * {PubKey, bigint} (the first is `auction`). A new leader must beat the top
 * score and the previous leader must sign off.
 */
class LeaderBoard extends StatefulSmartContract {
  leader: PubKey;
  topScore: bigint;

  constructor(leader: PubKey, topScore: bigint) {
    super(leader, topScore);
    this.leader = leader;
    this.topScore = topScore;
  }

  public claim(sig: Sig, newLeader: PubKey, score: bigint) {
    assert(checkSig(sig, this.leader));
    assert(score > this.topScore);
    this.leader = newLeader;
    this.topScore = score;
  }
}
