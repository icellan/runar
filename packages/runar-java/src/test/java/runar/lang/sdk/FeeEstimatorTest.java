package runar.lang.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FeeEstimatorTest {

    @Test
    void matchesGoOutputForSingleP2PKHDeployment() {
        // numInputs=1, lockingScriptByteLen=23 (P2PKH), feeRate=100.
        // Hand-computed against the Go formula:
        //   inputsSize          = 148
        //   contractOutputSize  = 8 + 1 + 23 = 32
        //   changeOutputSize    = 34
        //   txSize              = 10 + 148 + 32 + 34 = 224
        //   fee = (224*100 + 999) / 1000 = 23
        assertEquals(23L, FeeEstimator.estimateDeployFee(1, 23, 100L));
    }

    @Test
    void feeScalesLinearlyWithScriptSize() {
        long smallFee = FeeEstimator.estimateDeployFee(1, 100, 100L);
        long largeFee = FeeEstimator.estimateDeployFee(1, 1_000, 100L);
        assertTrue(largeFee > smallFee, "larger script must raise the fee");
        assertTrue(largeFee - smallFee >= (1_000 - 100) / 10, "fee should scale ~1 sat/10 bytes at 100 sat/KB");
    }

    @Test
    void feeScalesWithInputCount() {
        long oneInput = FeeEstimator.estimateDeployFee(1, 23, 100L);
        long threeInputs = FeeEstimator.estimateDeployFee(3, 23, 100L);
        assertTrue(threeInputs > oneInput);
    }

    @Test
    void zeroOrNegativeFeeRateFallsBackToDefault() {
        long a = FeeEstimator.estimateDeployFee(1, 23, 0L);
        long b = FeeEstimator.estimateDeployFee(1, 23, 100L);
        assertEquals(b, a);
    }

    @Test
    void varIntByteSizeMatchesSpec() {
        assertEquals(1, FeeEstimator.varIntByteSize(0));
        assertEquals(1, FeeEstimator.varIntByteSize(0xfc));
        assertEquals(3, FeeEstimator.varIntByteSize(0xfd));
        assertEquals(3, FeeEstimator.varIntByteSize(0xffff));
        assertEquals(5, FeeEstimator.varIntByteSize(0x10000));
        assertEquals(5, FeeEstimator.varIntByteSize(0xffffffffL));
        assertEquals(9, FeeEstimator.varIntByteSize(0x100000000L));
    }

    @Test
    void callFeeBreakdownReasonable() {
        long fee = FeeEstimator.estimateCallFee(
            /*contractInputScriptLen*/ 200,
            /*extraContractInputsScriptLen*/ 0,
            /*p2pkhFundingInputs*/ 0,
            new int[] { 50 }, // one contract output
            /*withChange*/ false,
            100L
        );
        assertTrue(fee > 0);
    }
}
