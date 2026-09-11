package runar.lang.sdk;

import java.math.BigInteger;
import java.util.List;

import org.junit.jupiter.api.Test;
import runar.lang.sdk.RunarArtifact.ABI;
import runar.lang.sdk.RunarArtifact.ABIConstructor;
import runar.lang.sdk.RunarArtifact.ABIParam;
import runar.lang.sdk.RunarArtifact.ConstructorSlot;

import static org.junit.jupiter.api.Assertions.*;

/**
 * N-070 (extract half) — {@code decodeSlotValue} must know every ABI type
 * spelling the compiler can emit.
 *
 * <p>{@code RabinSig} / {@code RabinPubKey} are {@code bigint} ALIASES
 * (runar-lang/src/types.ts:68-71) that {@code verifyRabinSig} consumes with
 * OP_MOD, i.e. as a Script NUMBER. They were absent from this tier's
 * int/bool predicates too, so a restored contract's modulus came back as the
 * little-endian hex string {@code "1581e97df4102211"} instead of the number.
 * Feed that back into a call and the rebuilt locking script no longer matches
 * what is on chain.
 *
 * <p>Java was already the ONLY tier of seven that tested both the canonical
 * {@code boolean} and the alias {@code bool}; those cases are pinned here as
 * controls so the six tiers catching up cannot drag this one the other way.
 */
class N070SlotTypesTest {

    private static final BigInteger MODULUS = new BigInteger("1234567890123456789");
    /** Minimal LE sign-magnitude push of MODULUS: 8 bytes. */
    private static final String RABIN_PUSH = "081581e97df4102211";
    private static final String BLOB = "04deadbeef";

    /** Template: {@code <modulus@0> 7c <flag@2> 7c <blob@4> ac}. */
    private static RunarArtifact artifact(String rabinType, String boolType) {
        return new RunarArtifact(
            "v0", "0", "N070",
            new ABI(new ABIConstructor(List.of(
                new ABIParam("modulus", rabinType, null),
                new ABIParam("flag", boolType, null),
                new ABIParam("blob", "ByteString", null))), List.of()),
            "007c007c00ac",
            null,
            null,
            List.of(),
            List.of(new ConstructorSlot(0, 0), new ConstructorSlot(1, 2), new ConstructorSlot(2, 4)),
            List.of(),
            null,
            null);
    }

    private static String script(String flagOpcode) {
        return RABIN_PUSH + "7c" + flagOpcode + "7c" + BLOB + "ac";
    }

    @Test
    void rabinSlotsExtractAsNumbers() {
        for (String typeName : List.of("RabinPubKey", "RabinSig")) {
            List<Object> args = ContractScript.extractConstructorArgs(artifact(typeName, "boolean"), script("51"));
            assertEquals(MODULUS, args.get(0), typeName + ": modulus must decode as a script number");
        }
    }

    @Test
    void canonicalBooleanSlotExtractsAsBoolean() {
        assertEquals(Boolean.TRUE, ContractScript.extractConstructorArgs(artifact("RabinPubKey", "boolean"), script("51")).get(1));
        assertEquals(Boolean.FALSE, ContractScript.extractConstructorArgs(artifact("RabinPubKey", "boolean"), script("00")).get(1));
    }

    @Test
    void booleanAndBoolSpellingsAgree() {
        for (String opcode : List.of("51", "00")) {
            Object canonical = ContractScript.extractConstructorArgs(artifact("RabinPubKey", "boolean"), script(opcode)).get(1);
            Object alias = ContractScript.extractConstructorArgs(artifact("RabinPubKey", "bool"), script(opcode)).get(1);
            assertEquals(canonical, alias, "opcode " + opcode);
        }
    }

    @Test
    void controlOtherTypesUnchanged() {
        for (String typeName : List.of("bigint", "int")) {
            List<Object> args = ContractScript.extractConstructorArgs(artifact(typeName, "bool"), script("51"));
            assertEquals(MODULUS, args.get(0), typeName);
        }
        // A ByteString slot still comes back as its hex payload, NOT a number,
        // and the walk past the wide Rabin push still lands on it.
        List<Object> args = ContractScript.extractConstructorArgs(artifact("RabinPubKey", "boolean"), script("51"));
        assertEquals("deadbeef", args.get(2));
        // S1: a 1-byte ByteString MINIMALDATA-encoded as OP_5 is reconstructed
        // from the opcode.
        List<Object> s1 = ContractScript.extractConstructorArgs(
            artifact("RabinPubKey", "boolean"), RABIN_PUSH + "7c517c55ac");
        assertEquals("05", s1.get(2));
    }
}
