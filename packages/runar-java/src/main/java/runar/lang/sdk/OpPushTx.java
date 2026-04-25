package runar.lang.sdk;

import java.io.ByteArrayOutputStream;

/**
 * OP_PUSHTX (sighash-injection) helper for {@code checkPreimage()}-style
 * covenant contracts.
 *
 * <p>The OP_PUSHTX technique relies on the spender pushing the BIP-143
 * sighash preimage into the unlocking script. The on-chain script then
 * derives the BIP-143 sighash and verifies it via OP_CHECKSIG against a
 * fixed-{@code k=1} signature derived algebraically from the preimage.
 * Producing the signature itself is an SDK-side concern handled by
 * {@link LocalSigner} / {@link ExternalSigner}; this helper only deals
 * with computing and splicing the <i>preimage</i> into the unlocking
 * script.
 *
 * <p>Byte-level parity with the Go ({@code sdk_oppushtx.go}), Python
 * ({@code oppushtx.py}), Rust ({@code oppushtx.rs}), and Zig
 * ({@code sdk_oppushtx.zig}) helpers — the produced preimage and
 * unlocking-script bytes must match for the same input.
 *
 * <p>Package-private to match the surrounding SDK style ({@link RawTx}
 * et al. are package-private). Tests in the same package can exercise
 * the helper directly.
 */
final class OpPushTx {

    /** Default BSV BIP-143 sighash flag: {@code SIGHASH_ALL | SIGHASH_FORKID}. */
    static final int SIGHASH_ALL_FORKID = 0x41;

    private OpPushTx() {}

    /**
     * Computes the BIP-143 sighash <i>preimage</i> (raw bytes — not the
     * double-SHA256 hash) for the given input.
     *
     * <p>Matches {@code _bip143_preimage} in {@code runar-py/runar/sdk/oppushtx.py}
     * byte-for-byte for the same inputs.
     *
     * @param tx          parsed transaction
     * @param inputIndex  index of the input being signed
     * @param scriptCode  the locking script of the UTXO being spent (or
     *                    the portion after OP_CODESEPARATOR for stateful
     *                    contracts)
     * @param satoshis    satoshi value of the UTXO being spent
     * @param sigHashFlag sighash flag byte (e.g.\ {@link #SIGHASH_ALL_FORKID})
     */
    static byte[] preimage(RawTx tx, int inputIndex, byte[] scriptCode, long satoshis, int sigHashFlag) {
        if (tx == null) throw new IllegalArgumentException("OpPushTx.preimage: tx is null");
        if (scriptCode == null) throw new IllegalArgumentException("OpPushTx.preimage: scriptCode is null");
        if (inputIndex < 0 || inputIndex >= tx.inputs.size()) {
            throw new IllegalArgumentException(
                "OpPushTx.preimage: inputIndex " + inputIndex
                    + " out of range (" + tx.inputs.size() + " inputs)"
            );
        }

        boolean anyoneCanPay = (sigHashFlag & 0x80) != 0;
        int baseType = sigHashFlag & 0x1f;

        byte[] hashPrevouts;
        byte[] hashSequence;
        byte[] hashOutputs;

        // hashPrevouts
        if (!anyoneCanPay) {
            ByteArrayOutputStream prevouts = new ByteArrayOutputStream();
            for (RawTx.Input in : tx.inputs) {
                writeReversed(prevouts, ScriptUtils.hexToBytes(in.prevTxid));
                writeLE32(prevouts, in.prevVout);
            }
            hashPrevouts = Hash160.doubleSha256(prevouts.toByteArray());
        } else {
            hashPrevouts = new byte[32];
        }

        // hashSequence
        if (!anyoneCanPay && baseType != 0x01 /*ALL*/ && baseType != 0x03 /*SINGLE*/) {
            // Strict BIP-143: zero hashSequence when not ALL/SINGLE/ANYONECANPAY-ANY.
            // RawTx.sighashBIP143 has the same logic — keep them in lock step.
            hashSequence = new byte[32];
        } else if (!anyoneCanPay) {
            ByteArrayOutputStream seqs = new ByteArrayOutputStream();
            for (RawTx.Input in : tx.inputs) {
                writeLE32(seqs, (int) in.sequence);
            }
            hashSequence = Hash160.doubleSha256(seqs.toByteArray());
        } else {
            hashSequence = new byte[32];
        }

        // hashOutputs
        if (baseType != 0x03 /*SINGLE*/ && baseType != 0x02 /*NONE*/) {
            ByteArrayOutputStream outs = new ByteArrayOutputStream();
            for (RawTx.Output o : tx.outputs) {
                writeLE64(outs, o.satoshis);
                byte[] script = ScriptUtils.hexToBytes(o.scriptPubKeyHex);
                writeVarInt(outs, script.length);
                outs.writeBytes(script);
            }
            hashOutputs = Hash160.doubleSha256(outs.toByteArray());
        } else {
            hashOutputs = new byte[32];
        }

        RawTx.Input signed = tx.inputs.get(inputIndex);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeLE32(out, tx.version);
        out.writeBytes(hashPrevouts);
        out.writeBytes(hashSequence);
        writeReversed(out, ScriptUtils.hexToBytes(signed.prevTxid));
        writeLE32(out, signed.prevVout);
        writeVarInt(out, scriptCode.length);
        out.writeBytes(scriptCode);
        writeLE64(out, satoshis);
        writeLE32(out, (int) signed.sequence);
        out.writeBytes(hashOutputs);
        writeLE32(out, tx.locktime);
        writeLE32(out, sigHashFlag);
        return out.toByteArray();
    }

    /**
     * Splices a push of {@code preimage} followed by pushes of each
     * extra arg (in order) into a Bitcoin Script unlocking-script byte
     * array.
     *
     * <p>Each push uses the minimal length-prefixed encoding from
     * {@link ScriptUtils#encodePushData(String)}. SIGHASH_ALL preimages
     * are typically 150-300 bytes and therefore compile to
     * {@code OP_PUSHDATA1 <len> <preimage>}, but this method does not
     * special-case that — it always picks the minimal encoding.
     *
     * @param preimage bytes to push first
     * @param extras   any additional dynamic args (sigs, pubkeys, etc.)
     */
    static byte[] buildUnlock(byte[] preimage, byte[]... extras) {
        if (preimage == null) throw new IllegalArgumentException("OpPushTx.buildUnlock: preimage is null");
        StringBuilder hex = new StringBuilder();
        hex.append(ScriptUtils.encodePushData(ScriptUtils.bytesToHex(preimage)));
        if (extras != null) {
            for (int i = 0; i < extras.length; i++) {
                byte[] e = extras[i];
                if (e == null) {
                    throw new IllegalArgumentException(
                        "OpPushTx.buildUnlock: extras[" + i + "] is null"
                    );
                }
                hex.append(ScriptUtils.encodePushData(ScriptUtils.bytesToHex(e)));
            }
        }
        return ScriptUtils.hexToBytes(hex.toString());
    }

    /**
     * Convenience: compute the preimage from the prepared {@code tx} +
     * {@code utxo}, then build a single-arg unlocking script that pushes
     * just the preimage. Callers that need additional dynamic args
     * should call {@link #preimage} and {@link #buildUnlock} directly.
     */
    static PushTxResult prepare(RawTx tx, int inputIndex, UTXO utxo, int sigHashFlag) {
        if (utxo == null) throw new IllegalArgumentException("OpPushTx.prepare: utxo is null");
        byte[] scriptCode = ScriptUtils.hexToBytes(utxo.scriptHex());
        byte[] pre = preimage(tx, inputIndex, scriptCode, utxo.satoshis(), sigHashFlag);
        byte[] unlock = buildUnlock(pre);
        return new PushTxResult(pre, unlock);
    }

    /** Result of {@link #prepare}: the BIP-143 preimage and the single-push unlocking script. */
    record PushTxResult(byte[] preimage, byte[] unlockingScript) {}

    // ------------------------------------------------------------------
    // Local byte-stream helpers (avoid round-tripping through hex).
    // ------------------------------------------------------------------

    private static void writeLE32(ByteArrayOutputStream out, int n) {
        out.write(n & 0xff);
        out.write((n >>> 8) & 0xff);
        out.write((n >>> 16) & 0xff);
        out.write((n >>> 24) & 0xff);
    }

    private static void writeLE64(ByteArrayOutputStream out, long n) {
        writeLE32(out, (int) (n & 0xffffffffL));
        writeLE32(out, (int) ((n >>> 32) & 0xffffffffL));
    }

    private static void writeVarInt(ByteArrayOutputStream out, long n) {
        if (n < 0xfdL) {
            out.write((int) n);
        } else if (n <= 0xffffL) {
            out.write(0xfd);
            out.write((int) (n & 0xff));
            out.write((int) ((n >>> 8) & 0xff));
        } else if (n <= 0xffffffffL) {
            out.write(0xfe);
            writeLE32(out, (int) n);
        } else {
            out.write(0xff);
            writeLE64(out, n);
        }
    }

    private static void writeReversed(ByteArrayOutputStream out, byte[] data) {
        for (int i = data.length - 1; i >= 0; i--) {
            out.write(data[i] & 0xff);
        }
    }
}
