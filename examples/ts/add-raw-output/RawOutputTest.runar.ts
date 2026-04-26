import { StatefulSmartContract } from 'runar-lang';

export class RawOutputTest extends StatefulSmartContract {
    count: bigint;
    constructor(count: bigint) { super(count); this.count = count; }

    public sendToScript(scriptBytes: ByteString) {
        this.addRawOutput(1000n, scriptBytes);
        this.count = this.count + 1n;
        this.addOutput(0n, this.count);
    }
}
