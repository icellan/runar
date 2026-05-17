from runar import (
    StatefulSmartContract, Bigint, ByteString, public, len_,
)


class BranchedReadonlyLen(StatefulSmartContract):
    """Exercises a state-mutating if/else branched on a read-only
    intrinsic value (len)."""

    count: Bigint
    tag: ByteString

    def __init__(self, count: Bigint, tag: ByteString):
        super().__init__(count, tag)
        self.count = count
        self.tag = tag

    @public
    def spend(self, scratch: ByteString):
        if len_(scratch) > 0:
            self.count = self.count + 1
            self.tag = scratch
        else:
            self.count = self.count - 1
            self.tag = b"\x30\x30"
        self.add_output(1000, self.count, self.tag)
