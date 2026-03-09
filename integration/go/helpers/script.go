package helpers

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

// EncodePushInt encodes a script number push as hex.
func EncodePushInt(n int64) string {
	if n == 0 {
		return "00" // OP_0
	}
	if n >= 1 && n <= 16 {
		return fmt.Sprintf("%02x", 0x50+n)
	}
	if n == -1 {
		return "4f" // OP_1NEGATE
	}

	negative := n < 0
	abs := n
	if negative {
		abs = -abs
	}

	var bytes []byte
	for abs > 0 {
		bytes = append(bytes, byte(abs&0xff))
		abs >>= 8
	}

	last := bytes[len(bytes)-1]
	if last&0x80 != 0 {
		if negative {
			bytes = append(bytes, 0x80)
		} else {
			bytes = append(bytes, 0x00)
		}
	} else if negative {
		bytes[len(bytes)-1] = last | 0x80
	}

	if len(bytes) <= 75 {
		return fmt.Sprintf("%02x", len(bytes)) + hex.EncodeToString(bytes)
	}
	return fmt.Sprintf("4c%02x", len(bytes)) + hex.EncodeToString(bytes)
}

// EncodePushBigInt encodes a *big.Int as a Bitcoin script number push.
func EncodePushBigInt(n *big.Int) string {
	if n.Sign() == 0 {
		return "00"
	}
	if n.IsInt64() {
		v := n.Int64()
		if v >= 1 && v <= 16 {
			return fmt.Sprintf("%02x", 0x50+v)
		}
	}

	abs := new(big.Int).Abs(n)
	absBytes := abs.Bytes() // big-endian
	le := make([]byte, len(absBytes))
	for i, b := range absBytes {
		le[len(absBytes)-1-i] = b
	}

	if le[len(le)-1]&0x80 != 0 {
		if n.Sign() < 0 {
			le = append(le, 0x80)
		} else {
			le = append(le, 0x00)
		}
	} else if n.Sign() < 0 {
		le[len(le)-1] |= 0x80
	}

	return EncodePushBytes(le)
}

// EncodePushBytes encodes variable-length byte data as a push-data hex string.
func EncodePushBytes(data []byte) string {
	n := len(data)
	if n == 0 {
		return "00" // OP_0
	}
	if n <= 75 {
		return fmt.Sprintf("%02x", n) + hex.EncodeToString(data)
	}
	if n <= 255 {
		return fmt.Sprintf("4c%02x", n) + hex.EncodeToString(data)
	}
	if n <= 65535 {
		return fmt.Sprintf("4d%02x%02x", n&0xff, (n>>8)&0xff) + hex.EncodeToString(data)
	}
	return fmt.Sprintf("4e%02x%02x%02x%02x", n&0xff, (n>>8)&0xff, (n>>16)&0xff, (n>>24)&0xff) + hex.EncodeToString(data)
}

// EncodePushBool encodes a boolean push as hex.
func EncodePushBool(b bool) string {
	if b {
		return "51"
	}
	return "00"
}

// EncodePushPoint encodes a secp256k1 point as a 64-byte push (x[32]||y[32] big-endian).
func EncodePushPoint(x, y *big.Int) string {
	pt := make([]byte, 64)
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(pt[32-len(xBytes):32], xBytes)
	copy(pt[64-len(yBytes):64], yBytes)
	return EncodePushBytes(pt)
}

// EncodeMethodIndex encodes a method dispatch index.
func EncodeMethodIndex(idx int) string {
	return EncodePushInt(int64(idx))
}
