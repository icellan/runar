// LeaderBoard -- F-352 second witness for the mutable-state shape
// {PubKey, bigint}.
const runar = @import("runar");

pub const LeaderBoard = struct {
    pub const Contract = runar.StatefulSmartContract;

    leader: runar.PubKey = "000000000000000000000000000000000000000000000000000000000000000000",
    topScore: i64 = 0,

    pub fn init(leader: runar.PubKey, topScore: i64) LeaderBoard {
        return .{
            .leader = leader,
            .topScore = topScore,
        };
    }

    pub fn claim(self: *LeaderBoard, sig: runar.Sig, newLeader: runar.PubKey, score: i64) void {
        runar.assert(runar.checkSig(sig, self.leader));
        runar.assert(score > self.topScore);
        self.leader = newLeader;
        self.topScore = score;
    }
};
