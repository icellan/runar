// IntentOutputP2PKH -- exercises the `requireOutputP2PKH` intent
// intrinsic. Asserts that output 0 of the spending transaction is a
// standard P2PKH output paying exactly `bondAmount` satoshis to
// `bondPKH`.
module IntentOutputP2PKH {
    use runar::types::{ByteString};

    resource struct IntentOutputP2PKH {
        bondPKH: ByteString,
        bondAmount: bigint,
        count: &mut bigint,
    }

    public fun payBond(contract: &mut IntentOutputP2PKH) {
        requireOutputP2PKH(0, contract.bondPKH, contract.bondAmount);
        contract.count = contract.count + 1;
    }
}
