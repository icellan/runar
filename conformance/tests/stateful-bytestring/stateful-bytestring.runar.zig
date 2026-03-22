const runar = @import("runar");

pub const MessageBoard = struct {
    pub const Contract = runar.StatefulSmartContract;

    message: runar.ByteString = "",
    owner: runar.PubKey,

    pub fn init(message: runar.ByteString, owner: runar.PubKey) MessageBoard {
        return .{
            .message = message,
            .owner = owner,
        };
    }

    pub fn post(self: *MessageBoard, newMessage: runar.ByteString) void {
        self.message = newMessage;
        runar.assert(true);
    }

    pub fn burn(self: *const MessageBoard, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
    }
};
