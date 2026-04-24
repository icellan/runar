package runar.lang.sdk;

/** Minimal raw-transaction hex parser. Inverse of {@link RawTx#toHex()}. */
final class RawTxParser {
    private RawTxParser() {}

    static RawTx parse(String txHex) {
        RawTx tx = new RawTx();
        int pos = 0;
        tx.version = readLE32(txHex, pos); pos += 8;
        long[] inputCountArr = readVarInt(txHex, pos);
        int inputCount = (int) inputCountArr[0];
        pos += (int) inputCountArr[1];
        for (int i = 0; i < inputCount; i++) {
            String prevTxidLE = txHex.substring(pos, pos + 64);
            pos += 64;
            int prevVout = readLE32(txHex, pos); pos += 8;
            long[] scriptLenArr = readVarInt(txHex, pos);
            int scriptLen = (int) scriptLenArr[0];
            pos += (int) scriptLenArr[1];
            String scriptSig = txHex.substring(pos, pos + scriptLen * 2);
            pos += scriptLen * 2;
            long sequence = Integer.toUnsignedLong(readLE32(txHex, pos));
            pos += 8;
            tx.addInput(ScriptUtils.reverseHex(prevTxidLE), prevVout, scriptSig);
            tx.inputs.get(tx.inputs.size() - 1).sequence = sequence;
        }
        long[] outputCountArr = readVarInt(txHex, pos);
        int outputCount = (int) outputCountArr[0];
        pos += (int) outputCountArr[1];
        for (int i = 0; i < outputCount; i++) {
            long sats = readLE64(txHex, pos); pos += 16;
            long[] scriptLenArr = readVarInt(txHex, pos);
            int scriptLen = (int) scriptLenArr[0];
            pos += (int) scriptLenArr[1];
            String scriptPubKey = txHex.substring(pos, pos + scriptLen * 2);
            pos += scriptLen * 2;
            tx.addOutput(sats, scriptPubKey);
        }
        tx.locktime = readLE32(txHex, pos);
        return tx;
    }

    private static int readLE32(String hex, int pos) {
        int b0 = Integer.parseInt(hex.substring(pos,     pos + 2), 16);
        int b1 = Integer.parseInt(hex.substring(pos + 2, pos + 4), 16);
        int b2 = Integer.parseInt(hex.substring(pos + 4, pos + 6), 16);
        int b3 = Integer.parseInt(hex.substring(pos + 6, pos + 8), 16);
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }

    private static long readLE64(String hex, int pos) {
        long lo = Integer.toUnsignedLong(readLE32(hex, pos));
        long hi = Integer.toUnsignedLong(readLE32(hex, pos + 8));
        return lo | (hi << 32);
    }

    /** Returns {@code {value, hexCharsConsumed}}. */
    private static long[] readVarInt(String hex, int pos) {
        int first = Integer.parseInt(hex.substring(pos, pos + 2), 16);
        if (first < 0xfd) return new long[] { first, 2 };
        if (first == 0xfd) {
            int lo = Integer.parseInt(hex.substring(pos + 2, pos + 4), 16);
            int hi = Integer.parseInt(hex.substring(pos + 4, pos + 6), 16);
            return new long[] { lo | (hi << 8), 6 };
        }
        if (first == 0xfe) {
            long v = Integer.toUnsignedLong(readLE32(hex, pos + 2));
            return new long[] { v, 10 };
        }
        long v = readLE64(hex, pos + 2);
        return new long[] { v, 18 };
    }
}
