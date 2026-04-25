package runar.lang.runtime;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * SLH-DSA (FIPS 205, Stateless Hash-Based Digital Signature Standard)
 * SHA-256 reference implementation. Supports all 6 SHA2 parameter sets
 * (128s/128f/192s/192f/256s/256f) for keygen, sign, and verify.
 *
 * <p>Mirrors the Go reference at {@code packages/runar-go/slh_dsa.go};
 * cross-language signatures are byte-identical.
 */
public final class SlhDsa {

    private SlhDsa() {}

    public static final class Params {
        public final String name;
        public final int n;       // hash output bytes (16, 24, 32)
        public final int h;       // total tree height
        public final int d;       // hypertree layers
        public final int hp;      // height of each subtree (h/d)
        public final int a;       // FORS tree height
        public final int k;       // number of FORS trees
        public final int w;       // Winternitz parameter (always 16)
        public final int len;     // WOTS+ chain count

        Params(String name, int n, int h, int d, int hp, int a, int k, int w) {
            this.name = name;
            this.n = n; this.h = h; this.d = d; this.hp = hp;
            this.a = a; this.k = k; this.w = w;
            this.len = wotsLen(n, w);
        }
    }

    private static int wotsLen(int n, int w) {
        int len1 = (int) Math.ceil((8.0 * n) / log2(w));
        int len2 = (int) Math.floor(log2((double) len1 * (w - 1)) / log2(w)) + 1;
        return len1 + len2;
    }

    private static double log2(double v) {
        return Math.log(v) / Math.log(2);
    }

    public static final Params SHA2_128s = new Params("SLH-DSA-SHA2-128s", 16, 63, 7, 9, 12, 14, 16);
    public static final Params SHA2_128f = new Params("SLH-DSA-SHA2-128f", 16, 66, 22, 3, 6, 33, 16);
    public static final Params SHA2_192s = new Params("SLH-DSA-SHA2-192s", 24, 63, 7, 9, 14, 17, 16);
    public static final Params SHA2_192f = new Params("SLH-DSA-SHA2-192f", 24, 66, 22, 3, 8, 33, 16);
    public static final Params SHA2_256s = new Params("SLH-DSA-SHA2-256s", 32, 64, 8, 8, 14, 22, 16);
    public static final Params SHA2_256f = new Params("SLH-DSA-SHA2-256f", 32, 68, 17, 4, 8, 35, 16);

    public static final class KeyPair {
        public final byte[] sk; // SK.seed || SK.prf || PK.seed || PK.root
        public final byte[] pk; // PK.seed || PK.root
        KeyPair(byte[] sk, byte[] pk) { this.sk = sk; this.pk = pk; }
    }

    // ===================================================================
    // ADRS (FIPS 205 §4.2)
    // ===================================================================

    private static final int ADRS_SIZE = 32;

    private static final int ADRS_WOTS_HASH = 0;
    private static final int ADRS_WOTS_PK   = 1;
    private static final int ADRS_TREE      = 2;
    private static final int ADRS_FORS_TREE = 3;
    private static final int ADRS_FORS_ROOTS = 4;
    private static final int ADRS_WOTS_PRF  = 5;
    private static final int ADRS_FORS_PRF  = 6;

    private static byte[] newAdrs() { return new byte[ADRS_SIZE]; }

    private static void setLayerAddress(byte[] adrs, int layer) {
        adrs[0] = (byte) (layer >>> 24);
        adrs[1] = (byte) (layer >>> 16);
        adrs[2] = (byte) (layer >>> 8);
        adrs[3] = (byte) layer;
    }

    private static void setTreeAddress(byte[] adrs, long tree) {
        // 12 bytes, big-endian, at offset 4..15.
        for (int i = 0; i < 12; i++) {
            adrs[4 + 11 - i] = (byte) ((tree >>> (8 * i)) & 0xff);
        }
    }

    private static void setType(byte[] adrs, int typ) {
        adrs[16] = (byte) (typ >>> 24);
        adrs[17] = (byte) (typ >>> 16);
        adrs[18] = (byte) (typ >>> 8);
        adrs[19] = (byte) typ;
        for (int i = 20; i < 32; i++) adrs[i] = 0;
    }

    private static void setKeyPairAddress(byte[] adrs, int kp) {
        adrs[20] = (byte) (kp >>> 24);
        adrs[21] = (byte) (kp >>> 16);
        adrs[22] = (byte) (kp >>> 8);
        adrs[23] = (byte) kp;
    }

    private static void setChainAddress(byte[] adrs, int chain) {
        adrs[24] = (byte) (chain >>> 24);
        adrs[25] = (byte) (chain >>> 16);
        adrs[26] = (byte) (chain >>> 8);
        adrs[27] = (byte) chain;
    }

    private static void setHashAddress(byte[] adrs, int hash) {
        adrs[28] = (byte) (hash >>> 24);
        adrs[29] = (byte) (hash >>> 16);
        adrs[30] = (byte) (hash >>> 8);
        adrs[31] = (byte) hash;
    }

    private static void setTreeHeight(byte[] adrs, int height) { setChainAddress(adrs, height); }
    private static void setTreeIndex(byte[] adrs, int index)   { setHashAddress(adrs, index); }

    private static int getKeyPairAddress(byte[] adrs) {
        return ((adrs[20] & 0xff) << 24)
             | ((adrs[21] & 0xff) << 16)
             | ((adrs[22] & 0xff) << 8)
             | (adrs[23] & 0xff);
    }

    /** SHA2-compressed ADRS: 22 bytes (drop the high u24 of layer/type). */
    private static byte[] compressAdrs(byte[] adrs) {
        byte[] c = new byte[22];
        c[0] = adrs[3];
        System.arraycopy(adrs, 8, c, 1, 8);
        c[9] = adrs[19];
        System.arraycopy(adrs, 20, c, 10, 12);
        return c;
    }

    // ===================================================================
    // Hash primitives (SHA-256)
    // ===================================================================

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] a : arrays) { System.arraycopy(a, 0, out, off, a.length); off += a.length; }
        return out;
    }

    private static byte[] trunc(byte[] data, int n) {
        return Arrays.copyOf(data, n);
    }

    private static byte[] toByte(int value, int n) {
        byte[] b = new byte[n];
        long v = value & 0xffffffffL;
        for (int i = n - 1; i >= 0 && v > 0; i--) {
            b[i] = (byte) (v & 0xff);
            v >>>= 8;
        }
        return b;
    }

    /** T_l(PK.seed, ADRS, M) = trunc_n(SHA-256(PK.seed || pad || ADRSc || M)) */
    private static byte[] T(byte[] pkSeed, byte[] adrs, byte[] msg, int n) {
        byte[] adrsC = compressAdrs(adrs);
        byte[] pad = new byte[64 - n];
        return trunc(sha256(concat(pkSeed, pad, adrsC, msg)), n);
    }

    private static byte[] PRF(byte[] pkSeed, byte[] skSeed, byte[] adrs, int n) {
        return T(pkSeed, adrs, skSeed, n);
    }

    private static byte[] PRFmsg(byte[] skPrf, byte[] optRand, byte[] msg, int n) {
        byte[] pad = new byte[64 - n];
        return trunc(sha256(concat(pad, skPrf, optRand, msg)), n);
    }

    /** Hmsg via MGF1-SHA-256. */
    private static byte[] Hmsg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] msg, int outLen) {
        byte[] seed = concat(R, pkSeed, pkRoot, msg);
        byte[] hash = sha256(seed);
        byte[] result = new byte[outLen];
        int offset = 0;
        int counter = 0;
        while (offset < outLen) {
            byte[] block = sha256(concat(hash, toByte(counter, 4)));
            int copyLen = Math.min(32, outLen - offset);
            System.arraycopy(block, 0, result, offset, copyLen);
            offset += copyLen;
            counter++;
        }
        return result;
    }

    // ===================================================================
    // WOTS+ (FIPS 205 §5)
    // ===================================================================

    private static byte[] wotsChain(byte[] x, int start, int steps, byte[] pkSeed, byte[] adrs, int n) {
        byte[] tmp = x.clone();
        for (int j = start; j < start + steps; j++) {
            setHashAddress(adrs, j);
            tmp = T(pkSeed, adrs, tmp, n);
        }
        return tmp;
    }

    private static int wotsLen1(int n, int w) {
        return (int) Math.ceil((8.0 * n) / log2(w));
    }

    private static int wotsLen2(int n, int w) {
        int l1 = wotsLen1(n, w);
        return (int) Math.floor(log2((double) l1 * (w - 1)) / log2(w)) + 1;
    }

    private static int[] baseW(byte[] msg, int w, int outLen) {
        int logW = (int) log2(w);
        int[] bits = new int[(msg.length * 8) / logW];
        int idx = 0;
        for (byte bb : msg) {
            int b = bb & 0xff;
            for (int j = 8 - logW; j >= 0; j -= logW) {
                if (idx < bits.length) bits[idx++] = (b >>> j) & (w - 1);
            }
        }
        if (idx > outLen) {
            int[] out = new int[outLen];
            System.arraycopy(bits, 0, out, 0, outLen);
            return out;
        }
        int[] out = new int[idx];
        System.arraycopy(bits, 0, out, 0, idx);
        return out;
    }

    private static int[] wotsAllDigits(byte[] msg, Params p) {
        int l1 = wotsLen1(p.n, p.w);
        int l2 = wotsLen2(p.n, p.w);
        int[] msgDigits = baseW(msg, p.w, l1);
        int csum = 0;
        for (int d : msgDigits) csum += (p.w - 1) - d;
        int csumBits = l2 * (int) log2(p.w);
        int shiftAmount = 8 - (csumBits % 8);
        if (shiftAmount == 8) shiftAmount = 0;
        int csumByteLen = (int) Math.ceil(csumBits / 8.0);
        byte[] csumBytes = toByte(csum << shiftAmount, csumByteLen);
        int[] csumDigits = baseW(csumBytes, p.w, l2);
        int[] all = new int[l1 + l2];
        System.arraycopy(msgDigits, 0, all, 0, l1);
        System.arraycopy(csumDigits, 0, all, l1, l2);
        return all;
    }

    private static byte[] wotsPkFromSig(byte[] sig, byte[] msg, byte[] pkSeed, byte[] adrs, Params p) {
        int n = p.n;
        int[] digits = wotsAllDigits(msg, p);
        int kpAddr = getKeyPairAddress(adrs);
        byte[] tmp = adrs.clone();
        setType(tmp, ADRS_WOTS_HASH);
        setKeyPairAddress(tmp, kpAddr);

        byte[][] parts = new byte[p.len][];
        for (int i = 0; i < p.len; i++) {
            setChainAddress(tmp, i);
            byte[] sigI = Arrays.copyOfRange(sig, i * n, (i + 1) * n);
            parts[i] = wotsChain(sigI, digits[i], p.w - 1 - digits[i], pkSeed, tmp, n);
        }

        byte[] pkAdrs = adrs.clone();
        setType(pkAdrs, ADRS_WOTS_PK);
        setKeyPairAddress(pkAdrs, kpAddr);
        return T(pkSeed, pkAdrs, concat(parts), n);
    }

    private static byte[] wotsSign(byte[] msg, byte[] skSeed, byte[] pkSeed, byte[] adrs, Params p) {
        int n = p.n;
        int[] digits = wotsAllDigits(msg, p);
        int kp = getKeyPairAddress(adrs);

        byte[][] parts = new byte[p.len][];
        for (int i = 0; i < p.len; i++) {
            byte[] skAdrs = adrs.clone();
            setType(skAdrs, ADRS_WOTS_PRF);
            setKeyPairAddress(skAdrs, kp);
            setChainAddress(skAdrs, i);
            setHashAddress(skAdrs, 0);
            byte[] sk = PRF(pkSeed, skSeed, skAdrs, n);

            byte[] chainAdrs = adrs.clone();
            setType(chainAdrs, ADRS_WOTS_HASH);
            setKeyPairAddress(chainAdrs, kp);
            setChainAddress(chainAdrs, i);
            parts[i] = wotsChain(sk, 0, digits[i], pkSeed, chainAdrs, n);
        }
        return concat(parts);
    }

    private static byte[] wotsPk(byte[] skSeed, byte[] pkSeed, byte[] adrs, Params p) {
        int n = p.n;
        int kp = getKeyPairAddress(adrs);
        byte[][] parts = new byte[p.len][];
        for (int i = 0; i < p.len; i++) {
            byte[] skAdrs = adrs.clone();
            setType(skAdrs, ADRS_WOTS_PRF);
            setKeyPairAddress(skAdrs, kp);
            setChainAddress(skAdrs, i);
            setHashAddress(skAdrs, 0);
            byte[] sk = PRF(pkSeed, skSeed, skAdrs, n);

            byte[] chainAdrs = adrs.clone();
            setType(chainAdrs, ADRS_WOTS_HASH);
            setKeyPairAddress(chainAdrs, kp);
            setChainAddress(chainAdrs, i);
            parts[i] = wotsChain(sk, 0, p.w - 1, pkSeed, chainAdrs, n);
        }

        byte[] pkAdrs = adrs.clone();
        setType(pkAdrs, ADRS_WOTS_PK);
        setKeyPairAddress(pkAdrs, kp);
        return T(pkSeed, pkAdrs, concat(parts), n);
    }

    // ===================================================================
    // XMSS (FIPS 205 §6)
    // ===================================================================

    private static byte[] xmssNode(byte[] skSeed, byte[] pkSeed, int idx, int height, byte[] adrs, Params p) {
        int n = p.n;
        if (height == 0) {
            byte[] leafAdrs = adrs.clone();
            setType(leafAdrs, ADRS_WOTS_HASH);
            setKeyPairAddress(leafAdrs, idx);
            return wotsPk(skSeed, pkSeed, leafAdrs, p);
        }
        byte[] left = xmssNode(skSeed, pkSeed, 2 * idx, height - 1, adrs, p);
        byte[] right = xmssNode(skSeed, pkSeed, 2 * idx + 1, height - 1, adrs, p);
        byte[] nodeAdrs = adrs.clone();
        setType(nodeAdrs, ADRS_TREE);
        setTreeHeight(nodeAdrs, height);
        setTreeIndex(nodeAdrs, idx);
        return T(pkSeed, nodeAdrs, concat(left, right), n);
    }

    private static byte[] xmssSign(byte[] msg, byte[] skSeed, byte[] pkSeed, int idx, byte[] adrs, Params p) {
        int hp = p.hp;
        byte[] sigAdrs = adrs.clone();
        setType(sigAdrs, ADRS_WOTS_HASH);
        setKeyPairAddress(sigAdrs, idx);
        byte[] sig = wotsSign(msg, skSeed, pkSeed, sigAdrs, p);

        byte[][] auth = new byte[hp][];
        for (int j = 0; j < hp; j++) {
            int sibling = (idx >>> j) ^ 1;
            auth[j] = xmssNode(skSeed, pkSeed, sibling, j, adrs, p);
        }

        byte[][] all = new byte[1 + hp][];
        all[0] = sig;
        System.arraycopy(auth, 0, all, 1, hp);
        return concat(all);
    }

    private static byte[] xmssPkFromSig(int idx, byte[] sigXmss, byte[] msg, byte[] pkSeed, byte[] adrs, Params p) {
        int n = p.n;
        int hp = p.hp;
        int wotsSigLen = p.len * n;
        byte[] wotsSig = Arrays.copyOfRange(sigXmss, 0, wotsSigLen);
        byte[] auth = Arrays.copyOfRange(sigXmss, wotsSigLen, sigXmss.length);

        byte[] wAdrs = adrs.clone();
        setType(wAdrs, ADRS_WOTS_HASH);
        setKeyPairAddress(wAdrs, idx);
        byte[] node = wotsPkFromSig(wotsSig, msg, pkSeed, wAdrs, p);

        byte[] treeAdrs = adrs.clone();
        setType(treeAdrs, ADRS_TREE);
        for (int j = 0; j < hp; j++) {
            byte[] authJ = Arrays.copyOfRange(auth, j * n, (j + 1) * n);
            setTreeHeight(treeAdrs, j + 1);
            setTreeIndex(treeAdrs, idx >>> (j + 1));
            if (((idx >>> j) & 1) == 0) {
                node = T(pkSeed, treeAdrs, concat(node, authJ), n);
            } else {
                node = T(pkSeed, treeAdrs, concat(authJ, node), n);
            }
        }
        return node;
    }

    // ===================================================================
    // FORS (FIPS 205 §8)
    // ===================================================================

    private static int extractForsIdx(byte[] md, int treeIdx, int a) {
        int bitStart = treeIdx * a;
        int byteStart = bitStart / 8;
        int bitOffset = bitStart % 8;
        int value = 0;
        int bitsNeeded = a;
        int bitsRead = 0;
        for (int i = byteStart; bitsRead < bitsNeeded; i++) {
            int b = i < md.length ? (md[i] & 0xff) : 0;
            int availBits = (i == byteStart) ? 8 - bitOffset : 8;
            int bitsToTake = Math.min(availBits, bitsNeeded - bitsRead);
            int shift = (i == byteStart) ? availBits - bitsToTake : 8 - bitsToTake;
            int mask = (1 << bitsToTake) - 1;
            value = (value << bitsToTake) | ((b >>> shift) & mask);
            bitsRead += bitsToTake;
        }
        return value;
    }

    private static byte[] forsSign(byte[] md, byte[] skSeed, byte[] pkSeed, byte[] adrs, Params p) {
        int n = p.n;
        int a = p.a;
        int k = p.k;
        byte[][] parts = new byte[k * (1 + a)][];
        int idxOut = 0;
        int kp = getKeyPairAddress(adrs);
        for (int i = 0; i < k; i++) {
            int idx = extractForsIdx(md, i, a);
            byte[] skAdrs = adrs.clone();
            setType(skAdrs, ADRS_FORS_PRF);
            setKeyPairAddress(skAdrs, kp);
            setTreeHeight(skAdrs, 0);
            setTreeIndex(skAdrs, i * (1 << a) + idx);
            byte[] sk = PRF(pkSeed, skSeed, skAdrs, n);
            parts[idxOut++] = sk;
            for (int j = 0; j < a; j++) {
                int sibling = (idx >>> j) ^ 1;
                parts[idxOut++] = forsNode(skSeed, pkSeed, sibling, j, adrs, i, p);
            }
        }
        return concat(parts);
    }

    private static byte[] forsNode(byte[] skSeed, byte[] pkSeed, int idx, int height, byte[] adrs, int treeIdx, Params p) {
        int n = p.n;
        int a = p.a;
        int kp = getKeyPairAddress(adrs);
        if (height == 0) {
            byte[] skAdrs = adrs.clone();
            setType(skAdrs, ADRS_FORS_PRF);
            setKeyPairAddress(skAdrs, kp);
            setTreeHeight(skAdrs, 0);
            setTreeIndex(skAdrs, treeIdx * (1 << a) + idx);
            byte[] sk = PRF(pkSeed, skSeed, skAdrs, n);
            byte[] leafAdrs = adrs.clone();
            setType(leafAdrs, ADRS_FORS_TREE);
            setKeyPairAddress(leafAdrs, kp);
            setTreeHeight(leafAdrs, 0);
            setTreeIndex(leafAdrs, treeIdx * (1 << a) + idx);
            return T(pkSeed, leafAdrs, sk, n);
        }
        byte[] left = forsNode(skSeed, pkSeed, 2 * idx, height - 1, adrs, treeIdx, p);
        byte[] right = forsNode(skSeed, pkSeed, 2 * idx + 1, height - 1, adrs, treeIdx, p);
        byte[] nodeAdrs = adrs.clone();
        setType(nodeAdrs, ADRS_FORS_TREE);
        setKeyPairAddress(nodeAdrs, kp);
        setTreeHeight(nodeAdrs, height);
        setTreeIndex(nodeAdrs, treeIdx * (1 << (a - height)) + idx);
        return T(pkSeed, nodeAdrs, concat(left, right), n);
    }

    private static byte[] forsPkFromSig(byte[] forsSig, byte[] md, byte[] pkSeed, byte[] adrs, Params p) {
        int n = p.n;
        int a = p.a;
        int k = p.k;
        int kp = getKeyPairAddress(adrs);
        byte[][] roots = new byte[k][];
        int offset = 0;
        for (int i = 0; i < k; i++) {
            int idx = extractForsIdx(md, i, a);
            byte[] sk = Arrays.copyOfRange(forsSig, offset, offset + n);
            offset += n;
            byte[] leafAdrs = adrs.clone();
            setType(leafAdrs, ADRS_FORS_TREE);
            setKeyPairAddress(leafAdrs, kp);
            setTreeHeight(leafAdrs, 0);
            setTreeIndex(leafAdrs, i * (1 << a) + idx);
            byte[] node = T(pkSeed, leafAdrs, sk, n);

            byte[] authAdrs = adrs.clone();
            setType(authAdrs, ADRS_FORS_TREE);
            setKeyPairAddress(authAdrs, kp);

            for (int j = 0; j < a; j++) {
                byte[] authJ = Arrays.copyOfRange(forsSig, offset, offset + n);
                offset += n;
                setTreeHeight(authAdrs, j + 1);
                setTreeIndex(authAdrs, (i * (1 << (a - j - 1))) + (idx >>> (j + 1)));
                if (((idx >>> j) & 1) == 0) {
                    node = T(pkSeed, authAdrs, concat(node, authJ), n);
                } else {
                    node = T(pkSeed, authAdrs, concat(authJ, node), n);
                }
            }
            roots[i] = node;
        }

        byte[] forsPkAdrs = adrs.clone();
        setType(forsPkAdrs, ADRS_FORS_ROOTS);
        setKeyPairAddress(forsPkAdrs, kp);
        return T(pkSeed, forsPkAdrs, concat(roots), n);
    }

    // ===================================================================
    // Top-level keygen / sign / verify
    // ===================================================================

    /** Generate an SLH-DSA keypair. {@code seed} must be {@code 3*params.n} bytes, or null for random. */
    public static KeyPair keygen(Params params, byte[] seed) {
        int n = params.n;
        byte[] s = seed;
        if (s == null) {
            s = new byte[3 * n];
            new SecureRandom().nextBytes(s);
        } else if (s.length != 3 * n) {
            throw new IllegalArgumentException("seed must be " + (3 * n) + " bytes");
        }
        byte[] skSeed = Arrays.copyOfRange(s, 0, n);
        byte[] skPrf  = Arrays.copyOfRange(s, n, 2 * n);
        byte[] pkSeed = Arrays.copyOfRange(s, 2 * n, 3 * n);

        byte[] adrs = newAdrs();
        setLayerAddress(adrs, params.d - 1);
        byte[] root = xmssNode(skSeed, pkSeed, 0, params.hp, adrs, params);

        byte[] sk = concat(skSeed, skPrf, pkSeed, root);
        byte[] pk = concat(pkSeed, root);
        return new KeyPair(sk, pk);
    }

    /** Deterministic sign (optRand = pkSeed). */
    public static byte[] sign(Params params, byte[] msg, byte[] sk) {
        int n = params.n;
        int d = params.d;
        int hp = params.hp;
        int k = params.k;
        int a = params.a;

        byte[] skSeed = Arrays.copyOfRange(sk, 0, n);
        byte[] skPrf  = Arrays.copyOfRange(sk, n, 2 * n);
        byte[] pkSeed = Arrays.copyOfRange(sk, 2 * n, 3 * n);
        byte[] pkRoot = Arrays.copyOfRange(sk, 3 * n, 4 * n);

        byte[] R = PRFmsg(skPrf, pkSeed, msg, n);

        int mdLen = (int) Math.ceil((k * a) / 8.0);
        int treeIdxLen = (int) Math.ceil((params.h - hp) / 8.0);
        int leafIdxLen = (int) Math.ceil(hp / 8.0);
        int digestLen = mdLen + treeIdxLen + leafIdxLen;
        byte[] digest = Hmsg(R, pkSeed, pkRoot, msg, digestLen);

        byte[] md = Arrays.copyOfRange(digest, 0, mdLen);
        long treeIdx = 0;
        for (int i = 0; i < treeIdxLen; i++) {
            treeIdx = (treeIdx << 8) | (digest[mdLen + i] & 0xff);
        }
        treeIdx &= (1L << (params.h - hp)) - 1;

        int leafIdx = 0;
        for (int i = 0; i < leafIdxLen; i++) {
            leafIdx = (leafIdx << 8) | (digest[mdLen + treeIdxLen + i] & 0xff);
        }
        leafIdx &= (1 << hp) - 1;

        byte[] forsAdrs = newAdrs();
        setTreeAddress(forsAdrs, treeIdx);
        setType(forsAdrs, ADRS_FORS_TREE);
        setKeyPairAddress(forsAdrs, leafIdx);
        byte[] forsSig = forsSign(md, skSeed, pkSeed, forsAdrs, params);
        byte[] forsPk = forsPkFromSig(forsSig, md, pkSeed, forsAdrs, params);

        byte[][] htParts = new byte[d][];
        byte[] currentMsg = forsPk;
        long currentTreeIdx = treeIdx;
        int currentLeafIdx = leafIdx;
        for (int layer = 0; layer < d; layer++) {
            byte[] layerAdrs = newAdrs();
            setLayerAddress(layerAdrs, layer);
            setTreeAddress(layerAdrs, currentTreeIdx);
            byte[] xmssSig = xmssSign(currentMsg, skSeed, pkSeed, currentLeafIdx, layerAdrs, params);
            htParts[layer] = xmssSig;
            currentMsg = xmssPkFromSig(currentLeafIdx, xmssSig, currentMsg, pkSeed, layerAdrs, params);
            currentLeafIdx = (int) (currentTreeIdx & ((1L << hp) - 1));
            currentTreeIdx = currentTreeIdx >>> hp;
        }

        byte[][] all = new byte[2 + d][];
        all[0] = R;
        all[1] = forsSig;
        System.arraycopy(htParts, 0, all, 2, d);
        return concat(all);
    }

    /** Verify an SLH-DSA signature. Returns false on length mismatch or root inequality. */
    public static boolean verify(Params params, byte[] msg, byte[] sig, byte[] pk) {
        int n = params.n;
        int d = params.d;
        int hp = params.hp;
        int k = params.k;
        int a = params.a;
        int len = params.len;

        if (pk.length != 2 * n) return false;
        byte[] pkSeed = Arrays.copyOfRange(pk, 0, n);
        byte[] pkRoot = Arrays.copyOfRange(pk, n, 2 * n);

        int offset = 0;
        if (sig.length < n) return false;
        byte[] R = Arrays.copyOfRange(sig, offset, offset + n);
        offset += n;

        int forsSigLen = k * (1 + a) * n;
        if (sig.length < offset + forsSigLen) return false;
        byte[] forsSig = Arrays.copyOfRange(sig, offset, offset + forsSigLen);
        offset += forsSigLen;

        int mdLen = (int) Math.ceil((k * a) / 8.0);
        int treeIdxLen = (int) Math.ceil((params.h - hp) / 8.0);
        int leafIdxLen = (int) Math.ceil(hp / 8.0);
        int digestLen = mdLen + treeIdxLen + leafIdxLen;
        byte[] digest = Hmsg(R, pkSeed, pkRoot, msg, digestLen);

        byte[] md = Arrays.copyOfRange(digest, 0, mdLen);
        long treeIdx = 0;
        for (int i = 0; i < treeIdxLen; i++) {
            treeIdx = (treeIdx << 8) | (digest[mdLen + i] & 0xff);
        }
        treeIdx &= (1L << (params.h - hp)) - 1;

        int leafIdx = 0;
        for (int i = 0; i < leafIdxLen; i++) {
            leafIdx = (leafIdx << 8) | (digest[mdLen + treeIdxLen + i] & 0xff);
        }
        leafIdx &= (1 << hp) - 1;

        byte[] forsAdrs = newAdrs();
        setTreeAddress(forsAdrs, treeIdx);
        setType(forsAdrs, ADRS_FORS_TREE);
        setKeyPairAddress(forsAdrs, leafIdx);
        byte[] currentMsg = forsPkFromSig(forsSig, md, pkSeed, forsAdrs, params);

        long currentTreeIdx = treeIdx;
        int currentLeafIdx = leafIdx;

        int xmssSigLen = (len + hp) * n;
        for (int layer = 0; layer < d; layer++) {
            if (sig.length < offset + xmssSigLen) return false;
            byte[] xmssSig = Arrays.copyOfRange(sig, offset, offset + xmssSigLen);
            offset += xmssSigLen;
            byte[] layerAdrs = newAdrs();
            setLayerAddress(layerAdrs, layer);
            setTreeAddress(layerAdrs, currentTreeIdx);
            currentMsg = xmssPkFromSig(currentLeafIdx, xmssSig, currentMsg, pkSeed, layerAdrs, params);
            currentLeafIdx = (int) (currentTreeIdx & ((1L << hp) - 1));
            currentTreeIdx = currentTreeIdx >>> hp;
        }

        return Arrays.equals(currentMsg, pkRoot);
    }
}
