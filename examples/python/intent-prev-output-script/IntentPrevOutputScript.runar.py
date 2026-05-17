from runar import (
    StatefulSmartContract, ByteString, Bigint, Readonly,
    public, assert_, len_, extract_prev_output_script,
)


class IntentPrevOutputScript(StatefulSmartContract):
    """Exercises the extract_prev_output_script intent intrinsic.

    Reads input 0's previous-output locking script via the
    witness-bridge pattern and asserts it is non-empty after the
    hash-equality check the intrinsic emits internally.
    """

    expected_hash: Readonly[ByteString]
    count: Bigint

    def __init__(self, expected_hash: ByteString, count: Bigint):
        super().__init__(expected_hash, count)
        self.expected_hash = expected_hash
        self.count = count

    @public
    def bind(self):
        s = extract_prev_output_script(0, self.expected_hash)
        assert_(len_(s) > 0)
        self.count = self.count + 1
