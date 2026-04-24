package runar.lang.sdk;

/**
 * Actual-script-size-aware fee estimation. Parity with Go
 * {@code EstimateDeployFee} / fee math inside {@code BuildCallTransaction}.
 *
 * <p>Fee rate is satoshis per 1000 bytes. BSV default is 100.
 */
public final class FeeEstimator {

    /** P2PKH input: prevTxid(32)+index(4)+scriptSig(~107)+sequence(4)+varint(1). */
    public static final int P2PKH_INPUT_SIZE = 148;
    /** P2PKH output: satoshis(8)+varint(1)+script(25). */
    public static final int P2PKH_OUTPUT_SIZE = 34;
    /** version(4)+input varint(1)+output varint(1)+locktime(4). */
    public static final int TX_OVERHEAD = 10;
    public static final long DEFAULT_FEE_RATE = 100L;

    private FeeEstimator() {}

    /**
     * Estimates the total fee for a contract deployment tx with N P2PKH
     * inputs, a contract output of the given locking-script length, and
     * a P2PKH change output.
     */
    public static long estimateDeployFee(int numInputs, int lockingScriptByteLen, long feeRate) {
        long rate = feeRate > 0 ? feeRate : DEFAULT_FEE_RATE;
        long inputsSize = (long) numInputs * P2PKH_INPUT_SIZE;
        long contractOutputSize = 8L + varIntByteSize(lockingScriptByteLen) + lockingScriptByteLen;
        long txSize = TX_OVERHEAD + inputsSize + contractOutputSize + P2PKH_OUTPUT_SIZE;
        return (txSize * rate + 999) / 1000;
    }

    /** Size of a Bitcoin varint encoding of {@code n}. */
    public static int varIntByteSize(long n) {
        if (n < 0xfdL) return 1;
        if (n <= 0xffffL) return 3;
        if (n <= 0xffffffffL) return 5;
        return 9;
    }

    /** Estimates fee for a call tx with actual-size inputs and outputs. */
    public static long estimateCallFee(
        int contractInputScriptLen,
        int extraContractInputsScriptLen,
        int p2pkhFundingInputs,
        int[] contractOutputScriptLens,
        boolean withChange,
        long feeRate
    ) {
        long rate = feeRate > 0 ? feeRate : DEFAULT_FEE_RATE;
        long inputsSize = 0;
        inputsSize += 32 + 4 + varIntByteSize(contractInputScriptLen) + contractInputScriptLen + 4L;
        inputsSize += extraContractInputsScriptLen; // already-computed total
        inputsSize += (long) p2pkhFundingInputs * P2PKH_INPUT_SIZE;

        long outputsSize = 0;
        for (int len : contractOutputScriptLens) {
            outputsSize += 8L + varIntByteSize(len) + len;
        }
        if (withChange) outputsSize += P2PKH_OUTPUT_SIZE;

        long txSize = TX_OVERHEAD + inputsSize + outputsSize;
        return (txSize * rate + 999) / 1000;
    }
}
