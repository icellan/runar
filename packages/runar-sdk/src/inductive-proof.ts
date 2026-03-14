/**
 * InductiveProofManager — manages ZKP proof lifecycle for InductiveSmartContract.
 *
 * The proof manager handles:
 * 1. Storing the current proof (from the previous spend)
 * 2. Generating a new proof for the next spend (delegated to an external prover)
 * 3. Verifying proofs off-chain before submitting transactions
 *
 * The on-chain `snark_verify` checks the proof against the genesis outpoint.
 * The proof attests that the entire chain from genesis to the current transaction
 * is valid.
 *
 * The manager integrates with `RunarContract.call()` to automatically update
 * the `_proof` field in the contract state before each spend.
 */

/** Size of the proof field in bytes (8 × 32-byte BN254 field elements). */
export const PROOF_SIZE = 256;

/** Zero proof (passes the OP_TRUE stub verifier). */
export const ZERO_PROOF = '00'.repeat(PROOF_SIZE);

/**
 * Proof generation function signature.
 * Takes genesis outpoint and previous state, returns a proof hex string.
 */
export type ProofGenerator = (
  genesisOutpoint: string,
  previousProof: string,
  parentTxId: string,
  parentState: Record<string, unknown>,
) => Promise<string>;

/**
 * Proof verification function signature.
 * Returns true if the proof is valid for the given public inputs.
 */
export type ProofVerifier = (
  proof: string,
  genesisOutpoint: string,
) => boolean;

/**
 * Manages proof state for an inductive contract instance.
 */
export class InductiveProofManager {
  private _proof: string;
  private _generator: ProofGenerator | null;
  private _verifier: ProofVerifier | null;

  constructor(
    initialProof?: string,
    generator?: ProofGenerator,
    verifier?: ProofVerifier,
  ) {
    this._proof = initialProof ?? ZERO_PROOF;
    this._generator = generator ?? null;
    this._verifier = verifier ?? null;
  }

  /** Get the current proof hex string. */
  get proof(): string {
    return this._proof;
  }

  /** Set the proof (e.g., after deserializing from chain state). */
  set proof(value: string) {
    if (value.length !== PROOF_SIZE * 2) {
      throw new Error(
        `InductiveProofManager: proof must be ${PROOF_SIZE} bytes (${PROOF_SIZE * 2} hex chars), got ${value.length / 2} bytes`,
      );
    }
    this._proof = value;
  }

  /**
   * Generate a new proof for the next spend.
   *
   * If no generator is configured, returns the zero proof (for stub verifier).
   * With a real prover, this would compute a Groth16 proof.
   */
  async generateProof(
    genesisOutpoint: string,
    parentTxId: string,
    parentState: Record<string, unknown>,
  ): Promise<string> {
    if (this._generator) {
      const newProof = await this._generator(
        genesisOutpoint,
        this._proof,
        parentTxId,
        parentState,
      );
      this._proof = newProof;
      return newProof;
    }
    // No generator — return zero proof (stub verifier accepts anything)
    return ZERO_PROOF;
  }

  /**
   * Verify a proof off-chain.
   *
   * Returns true if:
   * - No verifier is configured (stub mode, always passes)
   * - The verifier confirms the proof is valid
   */
  verifyProof(proof: string, genesisOutpoint: string): boolean {
    if (!this._verifier) return true;
    return this._verifier(proof, genesisOutpoint);
  }

  /** Check if this manager has a real proof generator. */
  get hasGenerator(): boolean {
    return this._generator !== null;
  }

  /** Check if this manager has a real proof verifier. */
  get hasVerifier(): boolean {
    return this._verifier !== null;
  }
}
