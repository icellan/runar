// Anyone — minimal `asm` raw-script contract (Solidity-like surface).
contract Anyone is UnsafeSmartContract {
    constructor() {}

    function unlock() public {
        asm(0x51, 0, 1);
    }
}
