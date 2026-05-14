use runar::prelude::*;

/// StackTrackerReproV10min — minimal reproducer for issue #36 in Rust form.
///
/// The first `if (... < outCount)` branch leaves `scriptLen`, `blobLen`, and
/// `blob` as branch-private locals on the stack. Without the lowerIf branch
/// reconciliation fix, post-ENDIF cleanup misindexed against `p` and the
/// downstream OP_SPLIT aborted. Mirrors the TS fixture in
/// examples/ts/if-without-else-multi-temp/.
#[runar::contract]
pub struct StackTrackerReproV10min {}

impl StackTrackerReproV10min {
    pub fn verify_mnee_tx_contains_both_outputs(
        &self,
        raw_tx: ByteString,
        expected_mnee_output_bytes: ByteString,
        expected_extra_data_output_bytes: ByteString,
    ) {
        let mut p: Bigint = 46;

        let out_count: Bigint = bin2num(cat(substr(raw_tx, p, 1), num2bin(0, 1)));
        assert!(out_count < 253);
        assert!(out_count <= 8);
        p = p + 1;

        let mut found_mnee: bool = false;
        let mut found_extra: bool = false;

        if 0 < out_count {
            let script_len: Bigint = bin2num(cat(substr(raw_tx, p + 8, 1), num2bin(0, 1)));
            assert!(script_len < 253);
            let blob_len: Bigint = 8 + 1 + script_len;
            let blob: ByteString = substr(raw_tx, p, blob_len);
            if blob == expected_mnee_output_bytes { found_mnee = true; }
            if blob == expected_extra_data_output_bytes { found_extra = true; }
            p = p + blob_len;
        }
        if 1 < out_count {
            let script_len: Bigint = bin2num(cat(substr(raw_tx, p + 8, 1), num2bin(0, 1)));
            assert!(script_len < 253);
            let blob_len: Bigint = 8 + 1 + script_len;
            let blob: ByteString = substr(raw_tx, p, blob_len);
            if blob == expected_mnee_output_bytes { found_mnee = true; }
            if blob == expected_extra_data_output_bytes { found_extra = true; }
            p = p + blob_len;
        }

        assert!(found_mnee);
        assert!(found_extra);
    }

    pub fn other(&self, x: ByteString) {
        assert!(x == x);
    }
}
