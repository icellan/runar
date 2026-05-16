// Anyone — minimal `asm` raw-script contract (Move-style surface).
unsafe module Anyone {
    public fun unlock() {
        asm(0x51, 0, 1);
    }
}
