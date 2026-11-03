import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sig } from 'runar-lang';

/**
 * Notary -- F-352 second witness for the mutable-state shape
 * {ByteString, PubKey, bigint} (the first is `annotated-vault`). The PubKey
 * comes FIRST here and the variable-length ByteString second, the reverse of
 * AnnotatedVault's order, so the state reader walks a different layout.
 */
class Notary extends StatefulSmartContract {
  signer: PubKey;
  note: ByteString;
  seq: bigint;

  constructor(signer: PubKey, note: ByteString, seq: bigint) {
    super(signer, note, seq);
    this.signer = signer;
    this.note = note;
    this.seq = seq;
  }

  public notarize(sig: Sig, nextNote: ByteString) {
    assert(checkSig(sig, this.signer));
    this.note = nextNote;
    this.seq = this.seq + 1n;
  }
}
