// Package sp1fri provides a Go decoder for SP1 v6.0.2 / Plonky3 STARK + FRI
// proofs serialized via postcard, plus type definitions matching the Plonky3
// proof struct tree.
//
// This package is the off-chain reference companion to the on-chain
// `runar.VerifySP1FRI` Bitcoin Script codegen at
// `compilers/go/codegen/sp1_fri.go`. Workflow:
//
//  1. Off-chain: a prover (e.g. SP1 SDK) emits a Plonky3 STARK proof as
//     postcard-encoded bytes. The Go decoder here parses those bytes into
//     Go structs.
//  2. Off-chain: a Go reference verifier (future work) re-runs the Plonky3
//     verification algorithm against the parsed structs to confirm the
//     proof is valid before paying broadcast fees.
//  3. On-chain: the unlocking script pushes individual proof fields plus a
//     concatenated proofBlob; the Bitcoin Script verifier hashes both and
//     asserts equality, then runs verification on the pre-pushed fields.
//
// Phase 1 of this package ships the postcard reader/writer + the decoder
// path against a real Plonky3 KoalaBear fixture. The reference verifier
// itself remains a deferred specialist port — see
// `docs/sp1-fri-verifier.md` §8.
package sp1fri

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// PostcardReader is a sequential decoder for the postcard wire format.
//
// Postcard rules used by the Plonky3 STARK proof tree:
//
//   - u8 / bool: 1 byte.
//   - u16/u32/u64/usize: unsigned LEB128 varint (continuation-bit prefix,
//     7 data bits per byte, little-endian, no zigzag for unsigned).
//   - i*  signed: zigzag-mapped to unsigned, then varint. Plonky3 STARK
//     proofs do not use signed integers in the wire format, so signed
//     decoding is omitted from this Phase 1 reader.
//   - bool: u8 (0x00 / 0x01).
//   - Option<T>: 1 byte tag (0x00 None, 0x01 Some) + body if Some.
//   - Vec<T>: varint length + items in order.
//   - struct: fields in declaration order, no separator.
//   - fixed array [T; N]: items in order, no length prefix.
//
// The reader does NOT validate end-of-stream; callers checking for
// trailing bytes use Remaining() after their top-level decode completes.
type PostcardReader struct {
	buf []byte
	pos int
}

// NewPostcardReader wraps bs as a postcard input stream.
func NewPostcardReader(bs []byte) *PostcardReader { return &PostcardReader{buf: bs} }

// Remaining returns the number of unread bytes.
func (r *PostcardReader) Remaining() int { return len(r.buf) - r.pos }

// Pos returns the current read offset, useful for diagnostic error messages.
func (r *PostcardReader) Pos() int { return r.pos }

func (r *PostcardReader) readByte() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, fmt.Errorf("postcard: unexpected EOF at offset %d", r.pos)
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

// ReadU8 reads a single byte.
func (r *PostcardReader) ReadU8() (uint8, error) { return r.readByte() }

// ReadBool reads a single byte and validates 0/1.
func (r *PostcardReader) ReadBool() (bool, error) {
	b, err := r.readByte()
	if err != nil {
		return false, err
	}
	switch b {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("postcard: bool tag %d at offset %d (must be 0 or 1)", b, r.pos-1)
	}
}

// ReadVarintU64 reads an unsigned LEB128 varint up to 64 bits.
//
// Postcard never uses more than 10 bytes for a u64 (7 × 9 = 63 bits +
// 1 final byte), so we cap at 10.
func (r *PostcardReader) ReadVarintU64() (uint64, error) {
	var result uint64
	shift := uint(0)
	for i := 0; i < 10; i++ {
		b, err := r.readByte()
		if err != nil {
			return 0, err
		}
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, nil
		}
		shift += 7
	}
	return 0, fmt.Errorf("postcard: varint overflow at offset %d", r.pos)
}

// ReadVarintU32 reads a varint and asserts it fits in u32.
func (r *PostcardReader) ReadVarintU32() (uint32, error) {
	v, err := r.ReadVarintU64()
	if err != nil {
		return 0, err
	}
	if v > 0xffff_ffff {
		return 0, fmt.Errorf("postcard: u32 overflow %d at offset %d", v, r.pos)
	}
	return uint32(v), nil
}

// ReadVarintUsize reads a varint sized for the platform's usize. Postcard
// emits usize as a varint; we accept any value that fits in u64 since the
// Plonky3 proof's degree_bits and Vec lengths fit comfortably.
func (r *PostcardReader) ReadVarintUsize() (uint64, error) { return r.ReadVarintU64() }

// ReadOption reads the option-tag byte and returns whether Some.
func (r *PostcardReader) ReadOption() (bool, error) { return r.ReadBool() }

// ReadVecLen reads a vec-length varint.
func (r *PostcardReader) ReadVecLen() (int, error) {
	n, err := r.ReadVarintU64()
	if err != nil {
		return 0, err
	}
	if n > uint64(len(r.buf))-uint64(r.pos)+1 {
		// crude over-allocation guard: a Vec of `n` items must fit in the
		// remaining bytes (each item is at least 1 byte).
		return 0, fmt.Errorf("postcard: implausible vec length %d at offset %d (remaining %d bytes)",
			n, r.pos, r.Remaining())
	}
	return int(n), nil
}

// ReadFixedBytes reads exactly n bytes verbatim.
func (r *PostcardReader) ReadFixedBytes(n int) ([]byte, error) {
	if r.Remaining() < n {
		return nil, fmt.Errorf("postcard: short read %d / %d at offset %d", r.Remaining(), n, r.pos)
	}
	out := make([]byte, n)
	copy(out, r.buf[r.pos:r.pos+n])
	r.pos += n
	return out, nil
}

// ErrTrailingBytes is returned when a top-level decode finishes with bytes
// still in the buffer — usually a struct mismatch or version skew.
var ErrTrailingBytes = errors.New("postcard: trailing bytes after top-level decode")

// PostcardWriter is the inverse encoder, used by round-trip tests to
// validate the decoder against a fixture without depending on a third-party
// postcard library.
type PostcardWriter struct{ w io.Writer }

// NewPostcardWriter wraps w as a postcard output stream.
func NewPostcardWriter(w io.Writer) *PostcardWriter { return &PostcardWriter{w: w} }

func (w *PostcardWriter) writeByte(b byte) error {
	_, err := w.w.Write([]byte{b})
	return err
}

// WriteU8 writes a single byte.
func (w *PostcardWriter) WriteU8(v uint8) error { return w.writeByte(v) }

// WriteBool writes 0/1.
func (w *PostcardWriter) WriteBool(v bool) error {
	if v {
		return w.writeByte(1)
	}
	return w.writeByte(0)
}

// WriteVarintU64 writes an unsigned LEB128 varint.
func (w *PostcardWriter) WriteVarintU64(v uint64) error {
	var buf [10]byte
	n := 0
	for v >= 0x80 {
		buf[n] = byte(v) | 0x80
		v >>= 7
		n++
	}
	buf[n] = byte(v)
	n++
	_, err := w.w.Write(buf[:n])
	return err
}

// WriteVarintU32 writes a u32 as varint.
func (w *PostcardWriter) WriteVarintU32(v uint32) error { return w.WriteVarintU64(uint64(v)) }

// WriteVarintUsize writes a usize-sized varint.
func (w *PostcardWriter) WriteVarintUsize(v uint64) error { return w.WriteVarintU64(v) }

// WriteOption writes the option tag.
func (w *PostcardWriter) WriteOption(some bool) error { return w.WriteBool(some) }

// WriteVecLen writes a vec length.
func (w *PostcardWriter) WriteVecLen(n int) error { return w.WriteVarintU64(uint64(n)) }

// WriteFixedBytes writes raw bytes verbatim.
func (w *PostcardWriter) WriteFixedBytes(bs []byte) error {
	_, err := w.w.Write(bs)
	return err
}

// WriteU32LE writes a 4-byte little-endian u32. Not used by postcard's
// default encoding (which uses varints) — included for callers that need
// to emit raw little-endian u32s alongside postcard data.
func (w *PostcardWriter) WriteU32LE(v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	_, err := w.w.Write(b[:])
	return err
}
