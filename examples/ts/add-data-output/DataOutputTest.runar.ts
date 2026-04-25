import { StatefulSmartContract, ByteString } from 'runar-lang';

export class DataOutputTest extends StatefulSmartContract {
    count: bigint;
    constructor(count: bigint) { super(count); this.count = count; }

    public publish(payload: ByteString) {
        this.count = this.count + 1n;
        this.addDataOutput(0n, payload);
    }
}
