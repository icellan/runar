import { SmartContract, assert, verifyWOTS } from 'runar-lang';
import type { ByteString } from 'runar-lang';

/**
 * Post-Quantum Wallet using WOTS+ (Winternitz One-Time Signature).
 *
 * Uses SHA-256-based hash chain verification with w=16, producing a
 * ~10 KB Bitcoin Script locking script. Each UTXO can be spent exactly
 * once with a valid WOTS+ signature — a natural fit for Bitcoin's UTXO model.
 *
 * Signature size: 2,144 bytes (67 chains x 32 bytes).
 * Public key size: 32 bytes (SHA-256 of concatenated chain endpoints).
 */
class PostQuantumWallet extends SmartContract {
  readonly pubkey: ByteString;

  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }

  public spend(msg: ByteString, sig: ByteString) {
    assert(verifyWOTS(msg, sig, this.pubkey));
  }
}
