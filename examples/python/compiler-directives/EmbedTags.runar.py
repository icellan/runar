from runar import (
    SmartContract, Addr, Bigint, Sig, PubKey, FixedArray, EmbedAlways,
    public, assert_, hash160, check_sig,
)


class EmbedTags(SmartContract):
    # Python port of examples/ts/compiler-directives/EmbedTags.runar.ts.
    #
    # EmbedAlways[...] on a FixedArray property applies to every expanded slot:
    # all three are kept although unlock reads only tags[1].

    pub_key_hash: Addr
    tags: EmbedAlways[FixedArray[Bigint, 3]] = [7, 9, 11]

    def __init__(self, pub_key_hash: Addr):
        super().__init__(pub_key_hash)
        self.pub_key_hash = pub_key_hash

    @public
    def unlock(self, sig: Sig, pub_key: PubKey, amount: Bigint):
        assert_(amount >= self.tags[1])
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
