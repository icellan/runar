import {
  SmartContract, assert, len,
  ecAdd, ecMul, ecMulGen, ecNegate, ecOnCurve,
  ecEncodeCompressed, ecMakePoint, ecPointX, ecPointY,
} from 'runar-lang';
import type { ByteString } from 'runar-lang';

class ECUnit extends SmartContract {
    readonly pubKey: ByteString;
    constructor(pubKey: ByteString) {
        super(pubKey);
        this.pubKey = pubKey;
    }

    public testOps() {
        const g = ecMulGen(1n);
        assert(ecOnCurve(g));
        const neg = ecNegate(g);
        assert(ecOnCurve(neg));
        const doubled = ecMul(g, 2n);
        assert(ecOnCurve(doubled));
        const sum = ecAdd(g, g);
        assert(ecOnCurve(sum));
        const x = ecPointX(g);
        const y = ecPointY(g);
        const rebuilt = ecMakePoint(x, y);
        assert(ecOnCurve(rebuilt));
        const compressed = ecEncodeCompressed(g);
        assert(len(compressed) == 33n);
        assert(true);
    }
}
