package runar.examples.blake3;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.blake3Compress;
import static runar.lang.Builtins.blake3Hash;

class Blake3Test extends SmartContract {

    @Readonly ByteString expected;

    Blake3Test(ByteString expected) {
        super(expected);
        this.expected = expected;
    }

    @Public
    void verifyCompress(ByteString chainingValue, ByteString block) {
        ByteString result = blake3Compress(chainingValue, block);
        assertThat(result.equals(expected));
    }

    @Public
    void verifyHash(ByteString message) {
        ByteString result = blake3Hash(message);
        assertThat(result.equals(expected));
    }
}
