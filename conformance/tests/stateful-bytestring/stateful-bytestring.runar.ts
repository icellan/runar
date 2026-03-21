import { StatefulSmartContract, assert, checkSig } from 'runar-lang';

class MessageBoard extends StatefulSmartContract {
  message: ByteString;
  readonly owner: PubKey;

  constructor(message: ByteString, owner: PubKey) {
    super(message, owner);
    this.message = message;
    this.owner = owner;
  }

  public post(newMessage: ByteString): void {
    this.message = newMessage;
    assert(true);
  }

  public burn(sig: Sig): void {
    assert(checkSig(sig, this.owner));
  }
}
