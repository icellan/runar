# N-268: an `embedAlways` marker on a readonly field on the Python surface.
# Only .runar.ts honours the directive; every other surface must refuse it
# with the one shared "not supported by the Python surface parser" message
# (mirrors N-244's sighash fix — before N-268 the Zig, Ruby and Java tiers
# each used their own, differently worded text here).
# With the marker replaced by prose, `metadata_id` is an ordinary unreferenced
# readonly field: every tier eliminates it by DCE, so this compiles to the
# same P2PKH-shaped script everywhere.
from runar import SmartContract, Addr, Sig, PubKey, ByteString, public, assert_, hash160, check_sig


class Meta(SmartContract):
    pub_key_hash: Addr
    # @embedAlways
    metadata_id: ByteString

    def __init__(self, pub_key_hash: Addr, metadata_id: ByteString):
        super().__init__(pub_key_hash, metadata_id)
        self.pub_key_hash = pub_key_hash
        self.metadata_id = metadata_id

    @public
    def unlock(self, sig: Sig, pub_key: PubKey):
        assert_(hash160(pub_key) == self.pub_key_hash)
        assert_(check_sig(sig, pub_key))
