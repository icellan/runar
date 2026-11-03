//! Known-answer vectors for the P-384 generator G, produced by Go's
//! crypto/elliptic (an implementation independent of runar-zig): G, -G = (x, p - y),
//! and the compressed encodings of both. Shared by P384EncodeNegate_test.zig and
//! assert_probe.zig so the in-process cases and the abort probes use one table.
const runar = @import("runar");

pub const g: runar.ByteString = runar.hexToBytes("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f");
pub const neg_g: runar.ByteString = runar.hexToBytes("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0");
pub const g_compressed: runar.ByteString = runar.hexToBytes("03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7");
pub const neg_g_compressed: runar.ByteString = runar.hexToBytes("02aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7");
