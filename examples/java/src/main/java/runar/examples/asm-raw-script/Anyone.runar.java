package runar.examples.asm_raw_script;

import runar.lang.UnsafeSmartContract;
import runar.lang.annotations.Public;
import static runar.lang.Builtins.asm;

class Anyone extends UnsafeSmartContract {
    Anyone() {
        super();
    }

    @Public
    void unlock() {
        asm("51", 0, 1);
    }
}
