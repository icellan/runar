package runar.lang.runtime;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import runar.lang.types.ByteString;

/**
 * A simulated BIP-143 sighash preimage. In real Bitcoin execution the
 * preimage is constructed by the transaction signer and pushed onto the
 * stack as a ByteString; the contract then calls {@code checkPreimage}
 * and extracts fields via the opcode-backed extractors. Under the
 * simulator, {@code checkPreimage} always succeeds, extractors return
 * sensible defaults (version = 1, sequence = 0xfffffffe, sighash =
 * SIGHASH_ALL | FORKID, etc.), and {@code extractOutputHash} echoes the
 * first 32 bytes of whatever preimage blob the test built.
 *
 * <p>Mirrors {@code packages/runar-lang/src/runtime/preimage.ts}.
 *
 * <p>Use {@link Builder#build()} to assemble a serialized preimage
 * matching the standard BIP-143 layout for round-trip tests.
 */
public final class Preimage {

    public static final byte[] ZERO_32 = new byte[32];
    public static final byte[] ZERO_36 = new byte[36];

    private final byte[] rawBytes;
    private final long version;
    private final byte[] hashPrevouts;
    private final byte[] hashSequence;
    private final byte[] outpoint;
    private final ByteString scriptCode;
    private final BigInteger amount;
    private final long sequence;
    private final byte[] hashOutputs;
    private final long locktime;
    private final long sighashType;

    private Preimage(Builder b) {
        this.version = b.version;
        this.hashPrevouts = b.hashPrevouts;
        this.hashSequence = b.hashSequence;
        this.outpoint = b.outpoint;
        this.scriptCode = b.scriptCode;
        this.amount = b.amount;
        this.sequence = b.sequence;
        this.hashOutputs = b.hashOutputs;
        this.locktime = b.locktime;
        this.sighashType = b.sighashType;
        this.rawBytes = serialize();
    }

    public long version() { return version; }
    public byte[] hashPrevouts() { return hashPrevouts.clone(); }
    public byte[] hashSequence() { return hashSequence.clone(); }
    public byte[] outpoint() { return outpoint.clone(); }
    public ByteString scriptCode() { return scriptCode; }
    public BigInteger amount() { return amount; }
    public long sequence() { return sequence; }
    public byte[] hashOutputs() { return hashOutputs.clone(); }
    public long locktime() { return locktime; }
    public long sighashType() { return sighashType; }

    public byte[] toBytes() { return rawBytes.clone(); }

    public ByteString toByteString() { return new ByteString(rawBytes); }

    public static Preimage zero() {
        return new Builder().build();
    }

    public static Builder builder() { return new Builder(); }

    /** Parse a serialized preimage back into a {@link Preimage}. */
    public static Preimage parse(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        Builder b = new Builder();
        b.version(bb.getInt() & 0xffffffffL);
        byte[] hp = new byte[32]; bb.get(hp); b.hashPrevouts(hp);
        byte[] hs = new byte[32]; bb.get(hs); b.hashSequence(hs);
        byte[] op = new byte[36]; bb.get(op); b.outpoint(op);
        // scriptCode is varint-prefixed; round-trip only needs to decode the length byte(s) we wrote.
        int scLen = readVarint(bb);
        byte[] sc = new byte[scLen]; bb.get(sc); b.scriptCode(new ByteString(sc));
        long amt = bb.getLong();
        b.amount(BigInteger.valueOf(amt));
        b.sequence(bb.getInt() & 0xffffffffL);
        byte[] ho = new byte[32]; bb.get(ho); b.hashOutputs(ho);
        b.locktime(bb.getInt() & 0xffffffffL);
        b.sighashType(bb.getInt() & 0xffffffffL);
        return b.build();
    }

    private static int readVarint(ByteBuffer bb) {
        int first = bb.get() & 0xff;
        if (first < 0xfd) return first;
        if (first == 0xfd) return bb.getShort() & 0xffff;
        if (first == 0xfe) return bb.getInt();
        throw new IllegalArgumentException("varint > int not supported");
    }

    private byte[] serialize() {
        int scLen = scriptCode.length();
        int scHeader = scLen < 0xfd ? 1 : (scLen <= 0xffff ? 3 : 5);
        int total = 4 + 32 + 32 + 36 + scHeader + scLen + 8 + 4 + 32 + 4 + 4;
        ByteBuffer bb = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) version);
        bb.put(hashPrevouts);
        bb.put(hashSequence);
        bb.put(outpoint);
        writeVarint(bb, scLen);
        bb.put(scriptCode.toByteArray());
        bb.putLong(amount.longValueExact());
        bb.putInt((int) sequence);
        bb.put(hashOutputs);
        bb.putInt((int) locktime);
        bb.putInt((int) sighashType);
        return bb.array();
    }

    private static void writeVarint(ByteBuffer bb, int v) {
        if (v < 0xfd) { bb.put((byte) v); return; }
        if (v <= 0xffff) { bb.put((byte) 0xfd); bb.putShort((short) v); return; }
        bb.put((byte) 0xfe); bb.putInt(v);
    }

    public static final class Builder {
        private long version = 1L;
        private byte[] hashPrevouts = ZERO_32.clone();
        private byte[] hashSequence = ZERO_32.clone();
        private byte[] outpoint = ZERO_36.clone();
        private ByteString scriptCode = new ByteString(new byte[0]);
        private BigInteger amount = BigInteger.valueOf(10000);
        private long sequence = 0xfffffffeL;
        private byte[] hashOutputs = ZERO_32.clone();
        private long locktime = 0L;
        private long sighashType = 0x41L; // SIGHASH_ALL | SIGHASH_FORKID

        public Builder version(long v) { this.version = v; return this; }
        public Builder hashPrevouts(byte[] v) { this.hashPrevouts = Arrays.copyOf(v, 32); return this; }
        public Builder hashSequence(byte[] v) { this.hashSequence = Arrays.copyOf(v, 32); return this; }
        public Builder outpoint(byte[] v) { this.outpoint = Arrays.copyOf(v, 36); return this; }
        public Builder scriptCode(ByteString v) { this.scriptCode = v; return this; }
        public Builder amount(BigInteger v) { this.amount = v; return this; }
        public Builder sequence(long v) { this.sequence = v; return this; }
        public Builder hashOutputs(byte[] v) { this.hashOutputs = Arrays.copyOf(v, 32); return this; }
        public Builder locktime(long v) { this.locktime = v; return this; }
        public Builder sighashType(long v) { this.sighashType = v; return this; }

        public Preimage build() { return new Preimage(this); }
    }

    // -----------------------------------------------------------------
    // Mock extractors — mirror runtime/preimage.ts defaults.
    // -----------------------------------------------------------------

    public static boolean checkPreimage(Preimage p) { return true; }

    public static BigInteger extractVersion(Preimage p) {
        return p == null ? BigInteger.ONE : BigInteger.valueOf(p.version);
    }

    public static ByteString extractHashPrevouts(Preimage p) {
        return new ByteString(p == null ? ZERO_32 : p.hashPrevouts);
    }

    public static ByteString extractHashSequence(Preimage p) {
        return new ByteString(p == null ? ZERO_32 : p.hashSequence);
    }

    public static ByteString extractOutpoint(Preimage p) {
        return new ByteString(p == null ? ZERO_36 : p.outpoint);
    }

    public static BigInteger extractInputIndex(Preimage p) { return BigInteger.ZERO; }

    public static ByteString extractScriptCode(Preimage p) {
        return p == null ? new ByteString(new byte[0]) : p.scriptCode;
    }

    public static BigInteger extractAmount(Preimage p) {
        return p == null ? BigInteger.valueOf(10000) : p.amount;
    }

    public static BigInteger extractSequence(Preimage p) {
        return p == null ? BigInteger.valueOf(0xfffffffeL) : BigInteger.valueOf(p.sequence);
    }

    /**
     * Returns the first 32 bytes of the raw preimage; tests that need
     * hash256(outputs) == extractOutputHash(preimage) to succeed should
     * pre-set hashOutputs = hash256(expectedOutputs) via the builder.
     */
    public static ByteString extractOutputHash(Preimage p) {
        if (p == null || p.rawBytes.length < 32) return new ByteString(ZERO_32);
        return new ByteString(Arrays.copyOfRange(p.rawBytes, 0, 32));
    }

    public static ByteString extractOutputs(Preimage p) {
        return new ByteString(p == null ? ZERO_32 : p.hashOutputs);
    }

    public static BigInteger extractLocktime(Preimage p) {
        return p == null ? BigInteger.ZERO : BigInteger.valueOf(p.locktime);
    }

    public static BigInteger extractSigHashType(Preimage p) {
        return p == null ? BigInteger.valueOf(0x41) : BigInteger.valueOf(p.sighashType);
    }
}
