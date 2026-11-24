// StatefulTerminalLoop -- a TERMINAL stateful method (no state write, so no
// injected continuation assert) whose bounded loop of asserts is followed by a
// final assert, which is the script result. Without it the method is refused
// in every tier (conformance/negatives N547).
module StatefulTerminalLoop {
    resource struct StatefulTerminalLoop {
        floor: &mut bigint,
        count: &mut bigint,
    }

    public fun close(contract: &mut StatefulTerminalLoop, x: bigint) {
        let i: bigint = 0;
        while (i < 2) {
            assert!(x >= contract.floor + i, 0);
            i = i + 1;
        };
        assert!(x > contract.count, 0);
    }
}
