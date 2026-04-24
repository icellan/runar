package runar.lang.sdk;

import java.util.ArrayList;
import java.util.List;

/**
 * Mutable builder for serialising a pre-signed or unsigned Bitcoin
 * transaction to raw hex. Minimal ruleset: version, inputs with
 * prevout + scriptSig + sequence, outputs with value + scriptPubKey,
 * locktime. Segwit / extended formats are not modeled.
 */
final class RawTx {

    int version = 1;
    int locktime = 0;
    final List<Input> inputs = new ArrayList<>();
    final List<Output> outputs = new ArrayList<>();

    static final class Input {
        String prevTxid;        // 32-byte hex, big-endian
        int prevVout;
        String scriptSigHex;
        long sequence = 0xffffffffL;
    }

    static final class Output {
        long satoshis;
        String scriptPubKeyHex;
    }

    void addInput(String prevTxid, int prevVout, String scriptSigHex) {
        Input in = new Input();
        in.prevTxid = prevTxid;
        in.prevVout = prevVout;
        in.scriptSigHex = scriptSigHex == null ? "" : scriptSigHex;
        inputs.add(in);
    }

    void addOutput(long satoshis, String scriptPubKeyHex) {
        Output o = new Output();
        o.satoshis = satoshis;
        o.scriptPubKeyHex = scriptPubKeyHex;
        outputs.add(o);
    }

    void setUnlockingScript(int inputIndex, String scriptSigHex) {
        inputs.get(inputIndex).scriptSigHex = scriptSigHex == null ? "" : scriptSigHex;
    }

    String toHex() {
        StringBuilder sb = new StringBuilder();
        sb.append(ScriptUtils.toLittleEndian32(version));
        sb.append(ScriptUtils.encodeVarInt(inputs.size()));
        for (Input in : inputs) {
            sb.append(ScriptUtils.reverseHex(in.prevTxid));
            sb.append(ScriptUtils.toLittleEndian32(in.prevVout));
            int scriptLen = in.scriptSigHex.length() / 2;
            sb.append(ScriptUtils.encodeVarInt(scriptLen));
            sb.append(in.scriptSigHex);
            sb.append(ScriptUtils.toLittleEndian32((int) in.sequence));
        }
        sb.append(ScriptUtils.encodeVarInt(outputs.size()));
        for (Output o : outputs) {
            sb.append(ScriptUtils.toLittleEndian64(o.satoshis));
            int scriptLen = o.scriptPubKeyHex.length() / 2;
            sb.append(ScriptUtils.encodeVarInt(scriptLen));
            sb.append(o.scriptPubKeyHex);
        }
        sb.append(ScriptUtils.toLittleEndian32(locktime));
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // BIP-143 sighash
    // ------------------------------------------------------------------

    static final int SIGHASH_ALL = 0x01;
    static final int SIGHASH_FORKID = 0x40;
    static final int SIGHASH_ALL_FORKID = SIGHASH_ALL | SIGHASH_FORKID;

    /**
     * Computes the BIP-143 / BSV SIGHASH_ALL|FORKID sighash for the
     * given input. {@code subscriptHex} is the locking script of the
     * UTXO being spent (or the code portion after OP_CODESEPARATOR for
     * stateful contracts).
     */
    byte[] sighashBIP143(int inputIndex, String subscriptHex, long inputSatoshis, int sighashType) {
        boolean anyoneCanPay = (sighashType & 0x80) != 0;
        int baseType = sighashType & 0x1f;

        byte[] hashPrevouts;
        byte[] hashSequence;
        byte[] hashOutputs;

        if (!anyoneCanPay) {
            StringBuilder prevouts = new StringBuilder();
            for (Input in : inputs) {
                prevouts.append(ScriptUtils.reverseHex(in.prevTxid));
                prevouts.append(ScriptUtils.toLittleEndian32(in.prevVout));
            }
            hashPrevouts = Hash160.doubleSha256(ScriptUtils.hexToBytes(prevouts.toString()));
        } else {
            hashPrevouts = new byte[32];
        }

        if (!anyoneCanPay && baseType != SIGHASH_ALL && baseType != 0x03 /*SINGLE*/) {
            hashSequence = new byte[32];
        } else if (!anyoneCanPay) {
            StringBuilder seqs = new StringBuilder();
            for (Input in : inputs) {
                seqs.append(ScriptUtils.toLittleEndian32((int) in.sequence));
            }
            hashSequence = Hash160.doubleSha256(ScriptUtils.hexToBytes(seqs.toString()));
        } else {
            hashSequence = new byte[32];
        }

        if (baseType != 0x03 /*SINGLE*/ && baseType != 0x02 /*NONE*/) {
            StringBuilder outs = new StringBuilder();
            for (Output o : outputs) {
                outs.append(ScriptUtils.toLittleEndian64(o.satoshis));
                int len = o.scriptPubKeyHex.length() / 2;
                outs.append(ScriptUtils.encodeVarInt(len));
                outs.append(o.scriptPubKeyHex);
            }
            hashOutputs = Hash160.doubleSha256(ScriptUtils.hexToBytes(outs.toString()));
        } else {
            hashOutputs = new byte[32];
        }

        Input signed = inputs.get(inputIndex);

        StringBuilder preimage = new StringBuilder();
        preimage.append(ScriptUtils.toLittleEndian32(version));
        preimage.append(ScriptUtils.bytesToHex(hashPrevouts));
        preimage.append(ScriptUtils.bytesToHex(hashSequence));
        preimage.append(ScriptUtils.reverseHex(signed.prevTxid));
        preimage.append(ScriptUtils.toLittleEndian32(signed.prevVout));
        int subLen = subscriptHex.length() / 2;
        preimage.append(ScriptUtils.encodeVarInt(subLen));
        preimage.append(subscriptHex);
        preimage.append(ScriptUtils.toLittleEndian64(inputSatoshis));
        preimage.append(ScriptUtils.toLittleEndian32((int) signed.sequence));
        preimage.append(ScriptUtils.bytesToHex(hashOutputs));
        preimage.append(ScriptUtils.toLittleEndian32(locktime));
        preimage.append(ScriptUtils.toLittleEndian32(sighashType));

        return Hash160.doubleSha256(ScriptUtils.hexToBytes(preimage.toString()));
    }
}
