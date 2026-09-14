/**
 * R-095 probe: variable-length state plus a readonly constructor property
 * whose baked width crosses the 75-byte direct-push ceiling.
 *
 * `memo` is a ByteString, so the state section has no compile-time length and
 * the compiler falls back to pinning SIZE(_codePart) against the code part's
 * own deployed byte length. `anchor` is a P384Point — 96 bytes — so the SDK
 * bakes it through OP_PUSHDATA1 (`4c 60 || <96>`, 98 bytes) over the 1-byte
 * OP_0 placeholder: the template grows by 97, not 96. Every other fixed-width
 * type fits in a direct push, so this is the only shape in which a
 * 1-byte-header assumption is observable.
 */
import { StatefulSmartContract, assert } from 'runar-lang';
import type { ByteString, P384Point } from 'runar-lang';

class VarLenP384Ctor extends StatefulSmartContract {
  memo: ByteString;
  readonly anchor: P384Point;

  constructor(memo: ByteString, anchor: P384Point) {
    super(memo, anchor);
    this.memo = memo;
    this.anchor = anchor;
  }

  public post(newMemo: ByteString, claimed: P384Point) {
    assert(this.anchor === claimed);
    this.memo = newMemo;
  }
}
