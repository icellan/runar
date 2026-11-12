import { StatefulSmartContract, ByteString } from 'runar-lang';

class InitLog extends StatefulSmartContract {
  log: ByteString = '00';
  constructor() { super(); }
  public append(entry: ByteString) { this.log = entry; }
}
