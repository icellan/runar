package runar.examples.covenantvault;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Addr;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;
import runar.lang.types.SigHashPreimage;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.cat;
import static runar.lang.Builtins.checkPreimage;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.extractOutputHash;
import static runar.lang.Builtins.hash256;
import static runar.lang.Builtins.num2bin;

/**
 * CovenantVault -- stateless Bitcoin covenant contract.
 *
 * <p>Ports {@code examples/go/covenant-vault/CovenantVault.runar.go}.
 *
 * <p>A covenant is a self-enforcing spending constraint: the locking
 * script dictates not just who can spend the funds, but how they may
 * be spent. This contract combines three verification layers:
 * <ol>
 *   <li>Owner authorisation via {@code checkSig}.</li>
 *   <li>Preimage verification via {@code checkPreimage}.</li>
 *   <li>Covenant rule: constructs the expected P2PKH output on-chain and
 *       verifies its hash against {@code extractOutputHash(preimage)}.</li>
 * </ol>
 *
 * <p>The output-construction step needs Rúnar's {@code cat}/{@code num2bin}
 * builtins, which are declared as intrinsics on the compiler side. The
 * Java form below spells them out via the static-imported builtins; on
 * the Rúnar side they compile to the same {@code OP_CAT}/{@code num2bin}
 * opcodes regardless of source language.
 */
class CovenantVault extends SmartContract {

    @Readonly PubKey owner;
    @Readonly Addr recipient;
    @Readonly Bigint minAmount;

    CovenantVault(PubKey owner, Addr recipient, Bigint minAmount) {
        super(owner, recipient, minAmount);
        this.owner = owner;
        this.recipient = recipient;
        this.minAmount = minAmount;
    }

    /**
     * Spend the vault. Owner-authorised and preimage-checked; the
     * covenant rule (output amount / destination) is implicit in the
     * {@link runar.lang.runtime.Preimage} that the simulator threads
     * through.
     */
    @Public
    void spend(Sig sig, SigHashPreimage txPreimage) {
        assertThat(checkSig(sig, this.owner));
        assertThat(checkPreimage(txPreimage));

        // Construct the expected P2PKH output on-chain:
        //   <8-byte LE amount> <varint(25)> <OP_DUP OP_HASH160 OP_PUSH(20) recipient OP_EQUALVERIFY OP_CHECKSIG>
        ByteString p2pkhScript = cat(cat(ByteString.fromHex("1976a914"), this.recipient), ByteString.fromHex("88ac"));
        ByteString expectedOutput = cat(num2bin(this.minAmount, Bigint.of(8)), p2pkhScript);

        // Verify the transaction's outputs match exactly.
        assertThat(hash256(expectedOutput).equals(extractOutputHash(txPreimage)));
    }
}
