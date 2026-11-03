import { StatefulSmartContract, assert, checkSig } from 'runar-lang';
import type { ByteString, PubKey, Sig } from 'runar-lang';

/**
 * AnnotatedVault — N-044 conformance fixture: a mutable variable-length
 * ByteString state field (`memo`) BEFORE a mutable PubKey (`owner`).
 *
 * Anyone may replace the memo; only the owner may withdraw. The on-chain state
 * reader decodes `memo`'s PUSHDATA length to find where `owner` starts, so that
 * length must be read as the UNSIGNED integer the writer meant. Before N-044 a
 * 128-byte memo (framed `4c 80`) read as length 0 and the memo's first 33 bytes
 * became `owner`: a stranger who annotated a memo beginning with their own
 * pubkey could then withdraw.
 */
class AnnotatedVault extends StatefulSmartContract {
  memo: ByteString;
  owner: PubKey;
  balance: bigint;

  constructor(memo: ByteString, owner: PubKey, balance: bigint) {
    super(memo, owner, balance);
    this.memo = memo;
    this.owner = owner;
    this.balance = balance;
  }

  /** Replace the memo. Anyone can call this method. */
  public annotate(nextMemo: ByteString) {
    this.memo = nextMemo;
  }

  /** Only the owner may spend. */
  public withdraw(sig: Sig) {
    assert(checkSig(sig, this.owner));
  }
}
