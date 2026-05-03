package runar.integration;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import runar.integration.helpers.ContractCompiler;
import runar.integration.helpers.IntegrationBase;
import runar.integration.helpers.IntegrationWallet;
import runar.integration.helpers.RpcProvider;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * NULLFAIL multi-method regression test -- chains advanceState calls
 * on a 4-method stateful contract where 3 methods use checkSig.
 *
 * <p>Reproduces a NULLFAIL bug where float64→int64 truncation in UTXO
 * satoshi conversion caused the P2PKH funding input's BIP-143 sighash
 * to drift by 1 sat. Ported from
 * {@code integration/go/nullfail_multimethod_test.go} (subset).
 */
class NullFailMultiMethodIntegrationTest extends IntegrationBase {

    private static final String SOURCE = """
        import {
          StatefulSmartContract, assert, checkSig, hash256, cat,
        } from 'runar-lang';
        import type { PubKey, Sig, ByteString } from 'runar-lang';

        class RollupContract extends StatefulSmartContract {
          stateRoot: ByteString;
          blockNumber: bigint;
          frozen: bigint;
          readonly governanceKey: PubKey;
          readonly verifyingKeyHash: ByteString;

          constructor(stateRoot: ByteString, blockNumber: bigint, frozen: bigint,
                      governanceKey: PubKey, verifyingKeyHash: ByteString) {
            super(stateRoot, blockNumber, frozen, governanceKey, verifyingKeyHash);
            this.stateRoot = stateRoot;
            this.blockNumber = blockNumber;
            this.frozen = frozen;
            this.governanceKey = governanceKey;
            this.verifyingKeyHash = verifyingKeyHash;
          }

          public advanceState(newStateRoot: ByteString, newBlockNumber: bigint,
                              batchData: ByteString, proofBlob: ByteString) {
            assert(this.frozen === 0n);
            assert(newBlockNumber > this.blockNumber);
            const expectedHash = hash256(cat(this.stateRoot, newStateRoot));
            assert(hash256(batchData) === expectedHash);
            this.stateRoot = newStateRoot;
            this.blockNumber = newBlockNumber;
          }

          public freeze(sig: Sig) {
            assert(checkSig(sig, this.governanceKey));
            this.frozen = 1n;
          }

          public unfreeze(sig: Sig) {
            assert(checkSig(sig, this.governanceKey));
            assert(this.frozen === 1n);
            this.frozen = 0n;
          }

          public upgrade(sig: Sig, newVerifyingKeyHash: ByteString) {
            assert(checkSig(sig, this.governanceKey));
          }
        }
        """;

    private static String sha256Hex(String hex) {
        try {
            byte[] data = new byte[hex.length() / 2];
            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            byte[] h = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : h) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String stateRoot(int n) {
        return sha256Hex("aa" + String.format("%02x", n));
    }

    private static RunarArtifact compileInline() {
        Path tmp;
        try {
            tmp = Files.createTempFile("runar-nullfail-", "RollupContract.runar.ts");
            Files.writeString(tmp, SOURCE);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return ContractCompiler.compileAbsolute(tmp);
    }

    @Test
    @DisplayName("chain 5 advanceState calls on a 4-method stateful contract")
    void chainAdvances() {
        RunarArtifact a = compileInline();
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 5.0);

        String vkHash = "cc" + "00".repeat(31);
        String initialRoot = "00".repeat(32);

        RunarContract contract = new RunarContract(a, List.of(
            initialRoot, BigInteger.ZERO, BigInteger.ZERO,
            wallet.pubKeyHex(), vkHash
        ));
        contract.deploy(provider, wallet.signer(), 1_000_000L);

        String prevRoot = initialRoot;
        String proofBlob = "ff" + "00".repeat(96);
        for (int block = 1; block <= 5; block++) {
            String newRoot = stateRoot(block);
            String batchData = prevRoot + newRoot;
            ArrayList<Object> args = new ArrayList<>();
            args.add(newRoot);
            args.add(BigInteger.valueOf(block));
            args.add(batchData);
            args.add(proofBlob);
            RunarContract.CallOutcome out = contract.call(
                "advanceState", args, null, provider, wallet.signer()
            );
            assertNotNull(out.txid(), "advance to block " + block);
            prevRoot = newRoot;
        }
    }
}
