import { SmartContract, assert, verifySLHDSA_SHA2_128s } from 'runar-lang';
import type { ByteString } from 'runar-lang';

/**
 * Post-Quantum Wallet using SLH-DSA-SHA2-128s (SPHINCS+).
 *
 * NIST FIPS 205, 128-bit post-quantum security, stateless.
 * Unlike WOTS+ (one-time), the same keypair can sign many messages.
 *
 * Public key: 32 bytes (PK.seed || PK.root).
 * Signature: 7,856 bytes.
 * Estimated script size: ~25 KB (when Bitcoin Script codegen is implemented).
 */
class SPHINCSWallet extends SmartContract {
  readonly pubkey: ByteString;

  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }

  public spend(msg: ByteString, sig: ByteString) {
    assert(verifySLHDSA_SHA2_128s(msg, sig, this.pubkey));
  }
}
