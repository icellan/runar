"""StackTrackerReproV10min — minimal reproducer for issue #36 in Python form.

The first ``if (... < out_count)`` branch leaves ``script_len``,
``blob_len``, and ``blob`` as branch-private locals on the stack. Without
the lowerIf branch reconciliation fix, post-ENDIF cleanup misindexed
against ``p`` and the downstream OP_SPLIT aborted. Mirrors the TS
fixture in examples/ts/if-without-else-multi-temp/.
"""

from runar import (
    SmartContract,
    Bigint,
    ByteString,
    public,
    assert_,
    bin2num,
    num2bin,
    cat,
    substr,
)


class StackTrackerReproV10min(SmartContract):
    def __init__(self):
        super().__init__()

    @public
    def verify_mnee_tx_contains_both_outputs(
        self,
        raw_tx: ByteString,
        expected_mnee_output_bytes: ByteString,
        expected_extra_data_output_bytes: ByteString,
    ):
        p: Bigint = 46

        out_count: Bigint = bin2num(cat(substr(raw_tx, p, 1), num2bin(0, 1)))
        assert_(out_count < 253)
        assert_(out_count <= 8)
        p = p + 1

        found_mnee: bool = False
        found_extra: bool = False

        if 0 < out_count:
            script_len: Bigint = bin2num(cat(substr(raw_tx, p + 8, 1), num2bin(0, 1)))
            assert_(script_len < 253)
            blob_len: Bigint = 8 + 1 + script_len
            blob: ByteString = substr(raw_tx, p, blob_len)
            if blob == expected_mnee_output_bytes:
                found_mnee = True
            if blob == expected_extra_data_output_bytes:
                found_extra = True
            p = p + blob_len
        if 1 < out_count:
            script_len: Bigint = bin2num(cat(substr(raw_tx, p + 8, 1), num2bin(0, 1)))
            assert_(script_len < 253)
            blob_len: Bigint = 8 + 1 + script_len
            blob: ByteString = substr(raw_tx, p, blob_len)
            if blob == expected_mnee_output_bytes:
                found_mnee = True
            if blob == expected_extra_data_output_bytes:
                found_extra = True
            p = p + blob_len

        assert_(found_mnee)
        assert_(found_extra)

    @public
    def other(self, x: ByteString):
        assert_(x == x)
