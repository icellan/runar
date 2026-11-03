from runar import (
    SmartContract, Addr, ByteString, Sig, PubKey, EmbedAlways,
    public, assert_, hash160, check_sig,
)


class Directives(SmartContract):
    # Python port of examples/ts/compiler-directives/Directives.runar.ts.
    #
    # The two compiler directives in their native Python spelling (N-093): the
    # wrapper type EmbedAlways[T] keeps deploy_tag in the locking script
    # although no method reads it, and public(sighash="SINGLE|FORKID")
    # declares the BIP-143 mode spend_single commits to.

    pub_key_hash: Addr
    deploy_tag: EmbedAlways[ByteString]

    def __init__(self, pub_key_hash: Addr, deploy_tag: ByteString):
        super().__init__(pub_key_hash, deploy_tag)
        self.pub_key_hash = pub_key_hash
        self.deploy_tag = deploy_tag

    @public
    def spend_all(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))

    @public(sighash="SINGLE|FORKID")
    def spend_single(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
