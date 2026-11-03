from runar import StatefulSmartContract, Ripemd160, Bigint, public, assert_


class DigestLog(StatefulSmartContract):
    """DigestLog -- F-352 second witness for the mutable-state shape
    {Ripemd160}."""

    digest: Ripemd160

    def __init__(self, digest: Ripemd160):
        super().__init__(digest)
        self.digest = digest

    @public
    def replace(self, new_digest: Ripemd160, version: Bigint):
        assert_(version > 0)
        self.digest = new_digest
