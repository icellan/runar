package runar.examples.crosscovenant;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.Sha256;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.bin2num;
import static runar.lang.Builtins.hash256;
import static runar.lang.Builtins.substr;

/**
 * CrossCovenantRef -- demonstrates reading another covenant's output.
 *
 * <p>Ports {@code examples/python/cross-covenant/CrossCovenantRef.runar.py}
 * to Java.
 *
 * <p>This pattern allows one covenant to verify data from a DIFFERENT
 * transaction's output, enabling cross-covenant communication on BSV.
 *
 * <h2>How it works</h2>
 * <ol>
 *   <li>The unlocking script passes the referenced output data as a
 *       parameter.</li>
 *   <li>The covenant hashes it and compares against a known script
 *       hash.</li>
 *   <li>If the hash matches, the data is authentic -- extract fields from
 *       it.</li>
 * </ol>
 *
 * <h2>Use cases</h2>
 * <ul>
 *   <li>Bridge covenant reading state covenant's state root.</li>
 *   <li>Side-chain anchor verifying main-chain commitments.</li>
 *   <li>Oracle covenant referencing price feed covenant's data.</li>
 * </ul>
 */
class CrossCovenantRef extends SmartContract {

    Sha256 sourceScriptHash;

    CrossCovenantRef(Sha256 sourceScriptHash) {
        super(sourceScriptHash);
        this.sourceScriptHash = sourceScriptHash;
    }

    /** Verify a referenced output and extract a 32-byte state root. */
    @Public
    void verifyAndExtract(
        ByteString referencedOutput,
        ByteString expectedStateRoot,
        Bigint stateRootOffset
    ) {
        // Step 1: Hash the referenced output and verify it matches the known script hash.
        ByteString outputHash = hash256(referencedOutput);
        assertThat(outputHash.equals(this.sourceScriptHash));

        // Step 2: Extract the state root from the referenced output.
        ByteString stateRoot = substr(referencedOutput, stateRootOffset.value(), Bigint.of(32).value());

        // Step 3: Verify the extracted state root matches the expected value.
        assertThat(stateRoot.equals(expectedStateRoot));
    }

    /** Verify a referenced output and extract a numeric value. */
    @Public
    void verifyAndExtractNumeric(
        ByteString referencedOutput,
        Bigint expectedValue,
        Bigint valueOffset,
        Bigint valueLen
    ) {
        ByteString outputHash = hash256(referencedOutput);
        assertThat(outputHash.equals(this.sourceScriptHash));

        ByteString valueBytes = substr(referencedOutput, valueOffset.value(), valueLen.value());
        java.math.BigInteger value = bin2num(valueBytes);
        assertThat(value.equals(expectedValue.value()));
    }
}
