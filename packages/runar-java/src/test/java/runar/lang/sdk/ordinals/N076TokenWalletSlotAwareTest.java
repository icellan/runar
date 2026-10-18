package runar.lang.sdk.ordinals;

import java.util.List;

import org.junit.jupiter.api.Test;

import runar.lang.sdk.MockProvider;
import runar.lang.sdk.MockSigner;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.UTXO;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * N-076: {@code TokenWallet.getUtxos} must discover a deployed token contract
 * with the slot-aware matcher ({@code ScriptUtils.matchesArtifact}), not a raw
 * prefix of the template. The template carries a constructor slot, a
 * codeSepIndex slot (baked as OP_1) and a {@code codePartLenSlots} field (the
 * deployed code-part length), none of which a literal prefix can equal.
 *
 * <p>Proves: a deployed instance of such a template (with a state section) is
 * found, while scripts that share the pre-slot prefix but differ after it,
 * carry a wrong code-part length, or are unrelated are not.
 * Does NOT prove: on-chain spendability of the matched UTXO, nor that an
 * artifact with only codeSepIndex slots (no constructor slots) is matched --
 * {@code matchesArtifact} itself compares such a template literally.
 */
class N076TokenWalletSlotAwareTest {

    // bytes: 76 a9 [00] 88 [00] 75 04 [00000000] ac
    //   ctor slot @2, codeSepIndex slot @4, codePartLen field @7
    private static final String ARTIFACT_JSON = """
        {
          "version": "runar-v0.1.0",
          "contractName": "FungibleToken",
          "abi": {"constructor": {"params": [{"name": "supply", "type": "bigint"}]}, "methods": []},
          "script": "76a9008800750400000000ac",
          "stateFields": [{"name": "balance", "type": "bigint", "index": 1}],
          "constructorSlots": [{"paramIndex": 0, "byteOffset": 2}],
          "codeSepIndexSlots": [{"byteOffset": 4, "codeSepIndex": 0}],
          "codePartLenSlots": [{"byteOffset": 7}]
        }
        """;

    /** supply = 02aabb, codeSepIndex baked as OP_1, code part is 14 bytes. */
    private static String deployed(String tail, String length) {
        return "76a9" + "02aabb" + "88" + "51" + "75" + "04" + length + tail + "6a" + "0100";
    }

    private static List<UTXO> discover(String script) {
        MockProvider provider = new MockProvider();
        MockSigner signer = new MockSigner();
        provider.addUtxo(signer.address(), new UTXO("aa".repeat(32), 0, 1000L, script));
        return new TokenWallet(RunarArtifact.fromJson(ARTIFACT_JSON), provider, signer).getUtxos();
    }

    @Test
    void findsADeployedSlottedInstance() {
        assertEquals(1, discover(deployed("ac", "0e000000")).size());
    }

    @Test
    void rejectsScriptsThatOnlyShareThePrefix() {
        assertEquals(0, discover(deployed("ad", "0e000000")).size(), "differs after the slots");
        assertEquals(0, discover(deployed("ac", "0f000000")).size(), "wrong code-part length");
        assertEquals(0, discover("76a914" + "11".repeat(20) + "88ac").size(), "unrelated script");
    }
}
