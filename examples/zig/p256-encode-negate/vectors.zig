//! Known-answer vectors for the P-256 generator G, produced by Go's
//! crypto/elliptic (an implementation independent of runar-zig): G, -G = (x, p - y),
//! and the compressed encodings of both. Shared by P256EncodeNegate_test.zig and
//! assert_probe.zig so the in-process cases and the abort probes use one table.
const runar = @import("runar");

pub const g: runar.ByteString = runar.hexToBytes("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
pub const neg_g: runar.ByteString = runar.hexToBytes("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a");
pub const g_compressed: runar.ByteString = runar.hexToBytes("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
pub const neg_g_compressed: runar.ByteString = runar.hexToBytes("026b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
