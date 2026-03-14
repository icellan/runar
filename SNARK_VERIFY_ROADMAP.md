# On-Chain SNARK Verification Roadmap

## Current State

The runtime Groth16 Bitcoin Script verifier is built and tested:
- 5.2M opcodes, ~32MB locking script
- Passes BSV Script interpreter for valid proofs
- Rejects tampered proofs
- Exported as `generateRuntimeVerifier(vk, numPublicInputs)` from `runar-zkp`

The compiler emits an OP_TRUE stub at the `snark_verify` position. Off-chain proof verification via `InductiveProofManager.verifyProof()` provides B2G security today. The artifact schema includes a `verificationKey` field for future on-chain wiring.

## Phase 1: SDK Verifier Composition

The ~32MB verifier script is too large to embed at compile time. Instead, the SDK should compose it at deployment time, similar to how constructor slots work.

### Tasks

1. **Add `snarkVerifySlot` to the artifact** — The compiler records the byte offset and length of the OP_TRUE stub in the locking script. This tells the SDK where to splice in the real verifier.

2. **SDK script splicing** — When deploying an InductiveSmartContract with a `verificationKey` in the artifact, the SDK:
   - Calls `generateRuntimeVerifier(vk, numPublicInputs)` to get verifier ops
   - Emits the ops to hex
   - Splices the verifier hex into the locking script at the recorded offset, replacing the OP_TRUE stub

3. **Proof deserialization preamble** — Before the verifier ops, emit a preamble that:
   - Splits the 256-byte `_proof` ByteString into 8 x 32-byte LE field elements via OP_SPLIT (7 splits)
   - The elements are already in the correct stack order: `[B.x.c0, B.x.c1, B.y.c0, B.y.c1, A.x, A.y, C.x, C.y]`
   - Converts `_genesisOutpoint` (36 bytes) to a BN254 field element via hash-to-field

4. **Altstack save/restore** — The verifier expects a clean stack (only proof elements + public inputs). Before the verifier:
   - Save all other stack items to altstack (count known at compile time from stackMap)
   - Run verifier (altstack usage is balanced — safe to have items below)
   - Restore saved items from altstack after verification

### Testing

- Compile an InductiveSmartContract with a mock VK
- Deploy via SDK with verifier splicing
- Execute a spend transaction through the BSV Script interpreter
- Verify both valid and tampered proofs

## Phase 2: Compiler-Level Verifier Injection (Optional)

Alternative to SDK splicing: have the compiler emit the full verifier directly. This makes the compiler output self-contained but produces ~32MB artifacts.

### Tasks

1. **Thread `snarkVerifierOps` to stack lowering** — Pass pre-generated StackOps from `CompileOptions` through to `lowerSnarkVerify`.

2. **Update `lowerSnarkVerify` in all 4 compilers** — When verifier ops are provided:
   - Emit proof deserialization (OP_SPLIT chain)
   - Emit altstack save for other stack items
   - Emit the raw verifier ops
   - Emit altstack restore
   - Push result onto stackMap

3. **Port to Go, Rust, Python compilers** — The verifier ops are language-agnostic StackOps. Each compiler needs to:
   - Accept verifier ops as input
   - Emit them in the `snark_verify` case of `lowerBinding`

## Phase 3: Real IVC Circuit

The mock prover generates algebraically valid Groth16 proofs but doesn't prove anything meaningful. A real implementation needs:

### R1CS Circuit Definition

Define an IVC (Incrementally Verifiable Computation) step circuit that proves:
- "I know a valid chain of transactions from genesis to this transaction"
- Public inputs: `_genesisOutpoint`, `parentStateHash`, `parentTxId`
- The circuit verifies the previous proof (recursive) and checks the state transition

### Trusted Setup

- Generate proving and verification keys via a structured reference string (SRS)
- The VK is embedded in the contract; the PK is used by the off-chain prover
- Multi-party computation (MPC) ceremony for production use

### Prover Integration

- Replace `mockProveWithVK` with a real Groth16 prover that:
  - Takes the R1CS constraint system + witness
  - Computes polynomial evaluations
  - Generates a valid proof
- Integrate with `InductiveProofManager.generateProof()`

### Nova Folding (Optimization)

For IVC efficiency, use Nova folding to accumulate proofs incrementally:
- Each spend folds the previous proof into the current one (O(1) prover time)
- Final proof is compressed to Groth16 for on-chain verification
- This avoids re-proving the entire chain from genesis on each spend

## Phase 4: Multi-Input DAG Support

The current IVC circuit assumes a single-parent chain topology. For fungible tokens that need UTXO merges:

- Extend the circuit to verify multiple parent proofs (DAG, not just chain)
- Each input UTXO provides its own proof; the circuit verifies all of them
- The merged output proof attests to the validity of all input chains back to genesis
- Public inputs include all parent `txid`s and the shared `_genesisOutpoint`

## File Reference

| Component | File |
|-----------|------|
| Runtime verifier codegen | `packages/runar-zkp/src/bn254/pairing-script.ts` |
| Verifier API | `packages/runar-zkp/src/groth16/verify-script.ts` |
| Proof serialization | `packages/runar-zkp/src/proof-serialize.ts` |
| Mock prover | `packages/runar-zkp/src/prover/prove.ts` |
| Mock setup | `packages/runar-zkp/src/prover/setup.ts` |
| Off-chain verification | `packages/runar-zkp/src/groth16/verify.ts` |
| SDK proof manager | `packages/runar-sdk/src/inductive-proof.ts` |
| Compiler snark_verify stub | `packages/runar-compiler/src/passes/05-stack-lower.ts` |
| Artifact schema (VK field) | `packages/runar-ir-schema/src/artifact.ts` |
| Verifier tests | `packages/runar-zkp/src/__tests__/groth16-script-exec.test.ts` |
