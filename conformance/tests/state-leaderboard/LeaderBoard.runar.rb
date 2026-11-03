require 'runar'

# LeaderBoard -- F-352 second witness for the mutable-state shape
# {PubKey, bigint}.
class LeaderBoard < Runar::StatefulSmartContract
  prop :leader, PubKey
  prop :top_score, Bigint

  def initialize(leader, top_score)
    super(leader, top_score)
    @leader = leader
    @top_score = top_score
  end

  runar_public sig: Sig, new_leader: PubKey, score: Bigint
  def claim(sig, new_leader, score)
    assert check_sig(sig, @leader)
    assert score > @top_score
    @leader = new_leader
    @top_score = score
  end
end
