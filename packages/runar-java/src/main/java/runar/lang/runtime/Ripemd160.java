package runar.lang.runtime;

/**
 * Pure-Java RIPEMD-160 implementation used as a fallback when BouncyCastle
 * is not on the classpath. JDK's {@code MessageDigest} does not include
 * RIPEMD-160 by default, so we roll a small port of RFC 1320's reference
 * implementation rather than pull a crypto jar into the production
 * classpath. Algorithm reference: RIPEMD-160 (Dobbertin, Bosselaers,
 * Preneel 1996).
 *
 * <p>Hash is deterministic and verified against the "abc" test vector
 * (8eb208f7e05d987a9b044a8e98c6b087f15a0bfc) in {@code MockCryptoTest}.
 */
final class Ripemd160 {

    private Ripemd160() {}

    static byte[] digest(byte[] input) {
        // Initial hash values.
        int h0 = 0x67452301;
        int h1 = 0xefcdab89;
        int h2 = 0x98badcfe;
        int h3 = 0x10325476;
        int h4 = 0xc3d2e1f0;

        // Pre-processing: pad with 0x80 then zeros, append original length in bits as LE 64-bit.
        long bitLen = (long) input.length * 8L;
        int padLen = 64 - ((input.length + 9) % 64);
        if (padLen == 64) padLen = 0;
        byte[] padded = new byte[input.length + 1 + padLen + 8];
        System.arraycopy(input, 0, padded, 0, input.length);
        padded[input.length] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            padded[padded.length - 8 + i] = (byte) (bitLen >>> (8 * i));
        }

        // Process each 64-byte block.
        int[] X = new int[16];
        for (int off = 0; off < padded.length; off += 64) {
            for (int j = 0; j < 16; j++) {
                X[j] = (padded[off + j * 4] & 0xff)
                    | ((padded[off + j * 4 + 1] & 0xff) << 8)
                    | ((padded[off + j * 4 + 2] & 0xff) << 16)
                    | ((padded[off + j * 4 + 3] & 0xff) << 24);
            }

            int al = h0, bl = h1, cl = h2, dl = h3, el = h4;
            int ar = h0, br = h1, cr = h2, dr = h3, er = h4;

            for (int j = 0; j < 80; j++) {
                int tl = rotl(al + fL(j, bl, cl, dl) + X[RL[j]] + KL(j), SL[j]) + el;
                al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = tl;

                int tr = rotl(ar + fL(79 - j, br, cr, dr) + X[RR[j]] + KR(j), SR[j]) + er;
                ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = tr;
            }

            int t = h1 + cl + dr;
            h1 = h2 + dl + er;
            h2 = h3 + el + ar;
            h3 = h4 + al + br;
            h4 = h0 + bl + cr;
            h0 = t;
        }

        byte[] out = new byte[20];
        putLE(out, 0, h0);
        putLE(out, 4, h1);
        putLE(out, 8, h2);
        putLE(out, 12, h3);
        putLE(out, 16, h4);
        return out;
    }

    private static int fL(int j, int x, int y, int z) {
        if (j < 16) return x ^ y ^ z;
        if (j < 32) return (x & y) | (~x & z);
        if (j < 48) return (x | ~y) ^ z;
        if (j < 64) return (x & z) | (y & ~z);
        return x ^ (y | ~z);
    }

    private static int KL(int j) {
        if (j < 16) return 0x00000000;
        if (j < 32) return 0x5a827999;
        if (j < 48) return 0x6ed9eba1;
        if (j < 64) return 0x8f1bbcdc;
        return 0xa953fd4e;
    }

    private static int KR(int j) {
        if (j < 16) return 0x50a28be6;
        if (j < 32) return 0x5c4dd124;
        if (j < 48) return 0x6d703ef3;
        if (j < 64) return 0x7a6d76e9;
        return 0x00000000;
    }

    // Message-word permutations for left & right lines.
    private static final int[] RL = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
        7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
        3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
        1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
        4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
    };

    private static final int[] RR = {
        5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
        6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
       15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
        8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
       12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
    };

    private static final int[] SL = {
       11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
        7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
       11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
       11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
        9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
    };

    private static final int[] SR = {
        8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
        9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
        9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
       15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
        8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
    };

    private static int rotl(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    private static void putLE(byte[] out, int off, int v) {
        out[off]     = (byte) v;
        out[off + 1] = (byte) (v >>> 8);
        out[off + 2] = (byte) (v >>> 16);
        out[off + 3] = (byte) (v >>> 24);
    }
}
