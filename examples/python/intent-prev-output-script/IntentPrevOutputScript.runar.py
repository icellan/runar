from runar import (
    StatefulSmartContract, ByteString, Bigint, Readonly,
    public, assert_, len_, extract_prev_output_script,
)


class IntentPrevOutputScript(StatefulSmartContract):
    """Exercises the extract_prev_output_script intent intrinsic.

    It does NOT read input 0 (W6 / GhostInput). The intrinsic asserts that a
    caller-supplied byte string hashes to expectedHash and returns it; this
    contract then asserts the string is non-empty. The first argument is a
    compile-time label naming the auto-injected witness parameter
    _prevOutScript_0, which the unlocking script supplies. There is no vin
    lookup, no parent transaction and no input-count check in the emitted
    script. For a construction that binds a specific companion INPUT, see
    examples/ts/companion-verifier/.
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
