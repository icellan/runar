// Command gen derives the SP1 FRI negative-test corruption fixtures from the
// base `minimal-guest/` fixture by byte-level mutation.
//
// Usage:
//
//	cd tests/vectors/sp1/fri/corruptions
//	go run ./gen.go --base ../minimal-guest --other ../evm-guest --out .
//
// Deterministic: the same base fixture always yields byte-identical output,
// including the per-directory README.md files. No prover run is required and
// no randomness is used anywhere — every mutation is the FIRST candidate in a
// fixed search order (see mutateVarint).
//
// This file is deliberately stdlib-only and self-contained: `tests/vectors/`
// is not part of any Go module (it is not listed in the repo-root `go.work`),
// so the generator cannot import `packages/runar-go/sp1fri`. The postcard
// walker below therefore re-implements the traversal in
// `packages/runar-go/sp1fri/decode.go` — if the proof struct shape changes
// upstream, both must be updated. The consuming tests in
// `compilers/go/codegen/sp1_fri_negative_test.go` re-derive every offset from
// the real decoder at test time and fail loudly on drift, so the duplication
// cannot silently rot.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// kbPrime is the KoalaBear modulus 2^31 - 2^24 + 1. Every field element on the
// postcard wire must decode below it (see sp1fri/decode.go::decodeKbElement).
const kbPrime = uint32(2130706433)

// truncateTailBytes is the number of trailing bytes stripped for the
// `truncated/` corruption (docs/sp1-fri-verifier.md §6).
const truncateTailBytes = 100

// allZerosSize is the size of the `all_zeros/` blob (200 KB, per §6).
const allZerosSize = 200 * 1024

func main() {
	base := flag.String("base", "../minimal-guest", "base fixture directory")
	other := flag.String("other", "../evm-guest", "a different guest program's fixture directory")
	out := flag.String("out", ".", "output directory (the corruptions/ root)")
	flag.Parse()

	proof, err := os.ReadFile(filepath.Join(*base, "proof.postcard"))
	check(err)
	pubVals, err := os.ReadFile(filepath.Join(*base, "public_values.hex"))
	check(err)
	basePub := strings.TrimSpace(string(pubVals))

	otherPubRaw, err := os.ReadFile(filepath.Join(*other, "public_values.hex"))
	check(err)
	otherPub := strings.TrimSpace(string(otherPubRaw))

	fields, err := walkProof(proof)
	check(err)
	byPath := map[string]field{}
	for _, f := range fields {
		byPath[f.path] = f
	}

	for _, c := range corruptions {
		dir := filepath.Join(*out, c.dir)
		check(os.MkdirAll(dir, 0o755))
		c.build(dir, proof, basePub, otherPub, byPath)
	}

	// bad_vk carries no fixture bytes — see its README for why.
	check(os.MkdirAll(filepath.Join(*out, "bad_vk"), 0o755))
	writeFile(filepath.Join(*out, "bad_vk", "README.md"), badVkReadme)

	fmt.Println("generated 7 corruption fixtures + bad_vk explainer")
}

// ---------------------------------------------------------------------------
// Corruption definitions
// ---------------------------------------------------------------------------

type corruption struct {
	dir   string
	build func(dir string, proof []byte, basePub, otherPub string, byPath map[string]field)
}

var corruptions = []corruption{
	{"bad_merkle", func(dir string, proof []byte, basePub, otherPub string, byPath map[string]field) {
		mutateProofField(dir, proof, basePub, byPath,
			"opening_proof.query_proofs[0].input_proof[0].opening_proof[0][0]",
			"bad_merkle",
			"Flip one byte in the first sibling digest of the first input-MMCS Merkle path.",
			"Merkle root recompute",
			"verify: FRI: fri: query 0 open_input: input MMCS verify (batch 0): verify_batch: cap mismatch at idx 0",
			"MATCHES the documented detection point. The mutated limb is a sibling\n"+
				"hash on the authentication path, so `VerifyBatch` recomputes a root that\n"+
				"does not equal the committed MerkleCap.")
	}},
	{"bad_folding", func(dir string, proof []byte, basePub, otherPub string, byPath map[string]field) {
		mutateProofField(dir, proof, basePub, byPath,
			"opening_proof.query_proofs[0].commit_phase_openings[0].sibling_values[0].c0",
			"bad_folding",
			"Change one FRI query opened evaluation (commit-phase round 0 sibling value,\n"+
				"which is the value fed into `foldRow`).",
			"FRI commit-phase MMCS opening (NOT a standalone colinearity check)",
			"verify: FRI: fri: query 0: round 0 MMCS: verify_batch: cap mismatch at idx 0",
			"DIVERGES from the documented \"colinearity check\". Plonky3 FRI has no\n"+
				"standalone colinearity assertion: every value the fold consumes is\n"+
				"Merkle-committed, so `VerifyBatchExt` for the commit-phase round fires\n"+
				"strictly before any folding arithmetic runs. The colinearity property is\n"+
				"enforced *by* that commitment check plus the final-poly equality, not by a\n"+
				"separate reachable check. See the corruptions README \"Detection-point\n"+
				"reality\" section.")
	}},
	{"bad_final_poly", func(dir string, proof []byte, basePub, otherPub string, byPath map[string]field) {
		mutateProofField(dir, proof, basePub, byPath,
			"opening_proof.final_poly[0].c0",
			"bad_final_poly",
			"Change the first limb of the first final-poly Ext4 coefficient.",
			"input-MMCS Merkle root recompute, via transcript divergence",
			"verify: FRI: fri: query 0 open_input: input MMCS verify (batch 0): verify_batch: cap mismatch at idx 0",
			"DIVERGES from the documented \"final-poly equality\". `final_poly` is observed\n"+
				"into the Fiat-Shamir transcript (fri.go step 4) BEFORE the query indices are\n"+
				"sampled, so mutating it re-randomises every query index; the Merkle proof\n"+
				"then authenticates the wrong leaf and MMCS fails first. The\n"+
				"`fri: query N final_poly mismatch` branch is unreachable by byte-level\n"+
				"corruption for exactly this reason.")
	}},
	{"wrong_public_values", func(dir string, proof []byte, basePub, otherPub string, byPath map[string]field) {
		raw, err := hex.DecodeString(basePub)
		check(err)
		if len(raw) < 12 {
			fail("public_values.hex too short: %d bytes", len(raw))
		}
		mutated := append([]byte(nil), raw...)
		// Third u32 (little-endian) is `x` = fib(7) = 21. Flip its low bit:
		// 21 -> 20. Deterministic, minimal, and keeps the 12-byte length.
		off := 8
		orig := mutated[off]
		mutated[off] ^= 0x01
		writeFile(filepath.Join(dir, "proof.postcard"), string(proof))
		writeFile(filepath.Join(dir, "public_values.hex"), hex.EncodeToString(mutated)+"\n")
		writeFile(filepath.Join(dir, "README.md"), renderReadme(readmeData{
			Name:      "wrong_public_values",
			Mutation:  "Flip one byte of `public_values.hex` (the low byte of the third u32).",
			Target:    "public_values.hex",
			Offset:    off,
			OrigByte:  orig,
			MutByte:   mutated[off],
			FieldPath: "public_values[2] (`x`, the claimed final Fibonacci value)",
			OrigVal:   uint64(binary.LittleEndian.Uint32(raw[8:12])),
			MutVal:    uint64(binary.LittleEndian.Uint32(mutated[8:12])),
			DocPoint:  "Transcript divergence",
			RealPoint: "Transcript divergence, surfacing at the commit-phase PoW witness",
			RealErr:   "verify: FRI: fri: commit-phase round 0 invalid PoW witness",
			Note: "MATCHES the documented detection point. `publicValues` is absorbed by the\n" +
				"challenger in verify.go step 2, so every downstream challenge (alpha, zeta,\n" +
				"every beta, every query index) shifts. The first check that consumes a\n" +
				"post-divergence challenge is the commit-phase grinding witness.",
			Unchanged: "proof.postcard",
		}))
	}},
	{"truncated", func(dir string, proof []byte, basePub, otherPub string, byPath map[string]field) {
		if len(proof) <= truncateTailBytes {
			fail("proof too short to truncate")
		}
		cut := proof[:len(proof)-truncateTailBytes]
		writeFile(filepath.Join(dir, "proof.postcard"), string(cut))
		writeFile(filepath.Join(dir, "public_values.hex"), basePub+"\n")
		writeFile(filepath.Join(dir, "README.md"), renderReadme(readmeData{
			Name:      "truncated",
			Mutation:  fmt.Sprintf("Strip the last %d bytes of `proof.postcard`.", truncateTailBytes),
			Target:    "proof.postcard",
			SizeNote:  fmt.Sprintf("%d bytes -> %d bytes", len(proof), len(cut)),
			DocPoint:  "Push-and-hash binding",
			RealPoint: "Two independent points, both asserted",
			RealErr: "postcard decode: `opening_proof: query_proofs: query[1]: commit_phase_openings:\n" +
				"step[0]: opening_proof: [3]: digest[4]: postcard: unexpected EOF at offset 1489`\n" +
				"push-and-hash: `OP_EQUALVERIFY` failure in the Step 1 SHA-256 binding",
			Note: "PARTIALLY MATCHES. Off-chain the truncated blob never reaches the verifier —\n" +
				"the postcard decoder hits EOF first. On-chain there is no decoder, so the\n" +
				"documented push-and-hash binding IS the detection point and is asserted\n" +
				"directly against `EmitProofBlobBindingHash` by the codegen negative test.",
			Unchanged: "public_values.hex",
		}))
	}},
	{"wrong_program", func(dir string, proof []byte, basePub, otherPub string, byPath map[string]field) {
		writeFile(filepath.Join(dir, "proof.postcard"), string(proof))
		writeFile(filepath.Join(dir, "public_values.hex"), otherPub+"\n")
		writeFile(filepath.Join(dir, "README.md"), renderReadme(readmeData{
			Name: "wrong_program",
			Mutation: "The unmodified `minimal-guest` proof paired with the `evm-guest` program's\n" +
				"public values. No byte of the proof is touched — the *binding* is wrong.",
			Target:    "public_values.hex (replaced wholesale)",
			DocPoint:  "Transcript divergence",
			RealPoint: "Transcript divergence, surfacing at the query-phase PoW witness",
			RealErr:   "verify: FRI: fri: invalid query PoW witness",
			Note: "MATCHES the documented detection point, but DEVIATES from the documented\n" +
				"*mutation*: the original matrix says \"minimal-guest proof + EVM-guest VK\n" +
				"hash\". No VK hash exists anywhere in this fixture tree (see ../bad_vk/),\n" +
				"so the program identity is expressed through the public values instead —\n" +
				"the only program-identifying input the reference verifier actually consumes.",
			Unchanged: "proof.postcard (byte-identical to minimal-guest)",
		}))
	}},
	{"all_zeros", func(dir string, proof []byte, basePub, otherPub string, byPath map[string]field) {
		writeFile(filepath.Join(dir, "proof.postcard"), string(make([]byte, allZerosSize)))
		writeFile(filepath.Join(dir, "public_values.hex"), basePub+"\n")
		writeFile(filepath.Join(dir, "README.md"), renderReadme(readmeData{
			Name:      "all_zeros",
			Mutation:  fmt.Sprintf("%d bytes of 0x00 in place of `proof.postcard`.", allZerosSize),
			Target:    "proof.postcard",
			SizeNote:  fmt.Sprintf("%d bytes -> %d bytes", len(proof), allZerosSize),
			DocPoint:  "bincode length / hash",
			RealPoint: "postcard top-level length check",
			RealErr:   "postcard: trailing bytes after top-level decode: 204785 bytes left",
			Note: "MATCHES the documented detection point. An all-zero buffer decodes as a\n" +
				"structurally minimal proof (every Vec length is 0) and consumes 15 of the\n" +
				"204800 bytes; the strict trailing-bytes check in `DecodeProof` rejects it.",
			Unchanged: "public_values.hex",
		}))
	}},
}

// mutateProofField applies the first length-preserving single-byte mutation to
// the KoalaBear element at `path` and writes the fixture directory.
func mutateProofField(dir string, proof []byte, basePub string, byPath map[string]field,
	path, name, mutation, docPoint, realErr, note string) {
	f, ok := byPath[path]
	if !ok {
		fail("field path not found in fixture: %s", path)
	}
	off, orig, mut, newVal, ok := mutateVarint(proof, f.off, f.n)
	if !ok {
		fail("no length-preserving mutation found for %s", path)
	}
	mutated := append([]byte(nil), proof...)
	mutated[off] = mut

	writeFile(filepath.Join(dir, "proof.postcard"), string(mutated))
	writeFile(filepath.Join(dir, "public_values.hex"), basePub+"\n")
	writeFile(filepath.Join(dir, "README.md"), renderReadme(readmeData{
		Name:      name,
		Mutation:  mutation,
		Target:    "proof.postcard",
		Offset:    off,
		OrigByte:  orig,
		MutByte:   mut,
		FieldPath: path,
		OrigVal:   uint64(f.val),
		MutVal:    uint64(newVal),
		VarintNote: fmt.Sprintf("field varint spans bytes [%d, %d) — the mutation keeps the "+
			"varint length identical so the file size and every later offset are unchanged",
			f.off, f.off+f.n),
		DocPoint:  docPointFor(name),
		RealPoint: docPoint,
		RealErr:   realErr,
		Note:      note,
		Unchanged: "public_values.hex",
	}))
}

func docPointFor(name string) string {
	switch name {
	case "bad_merkle":
		return "Merkle root recompute"
	case "bad_folding":
		return "Colinearity check"
	case "bad_final_poly":
		return "Final-poly equality"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Mutation search
// ---------------------------------------------------------------------------

// mutateVarint returns the first single-byte, length-preserving mutation of the
// LEB128 varint at [off, off+n) whose decoded value is still a valid canonical
// KoalaBear element and differs from the original.
//
// Search order (fixed, hence deterministic): byte index ascending, then bit
// index 0..6 ascending. Bit 7 is the LEB128 continuation bit and is never
// touched, which is what guarantees the varint keeps its byte length — so the
// mutation is a true in-place single-byte edit and no downstream offset moves.
func mutateVarint(bs []byte, off, n int) (byteOff int, orig, mut byte, newVal uint32, ok bool) {
	origVal, err := decodeVarintExact(bs[off : off+n])
	if err != nil {
		return 0, 0, 0, 0, false
	}
	for j := 0; j < n; j++ {
		for b := 0; b < 7; b++ {
			cand := append([]byte(nil), bs[off:off+n]...)
			cand[j] ^= 1 << uint(b)
			v, err := decodeVarintExact(cand)
			if err != nil || v >= kbPrime || v == origVal {
				continue
			}
			return off + j, bs[off+j], cand[j], v, true
		}
	}
	return 0, 0, 0, 0, false
}

// decodeVarintExact decodes bs as a single LEB128 varint and requires that it
// consumes bs exactly (no short read, no trailing byte).
func decodeVarintExact(bs []byte) (uint32, error) {
	var result uint64
	shift := uint(0)
	for i := 0; i < len(bs); i++ {
		result |= uint64(bs[i]&0x7f) << shift
		if bs[i]&0x80 == 0 {
			if i != len(bs)-1 {
				return 0, fmt.Errorf("varint ended early")
			}
			if result > 0xffff_ffff {
				return 0, fmt.Errorf("u32 overflow")
			}
			return uint32(result), nil
		}
		shift += 7
	}
	return 0, fmt.Errorf("varint truncated")
}

// ---------------------------------------------------------------------------
// Postcard walker — mirrors packages/runar-go/sp1fri/decode.go
// ---------------------------------------------------------------------------

type field struct {
	path string
	off  int
	n    int
	val  uint32
}

type reader struct {
	buf []byte
	pos int
	out []field
	err error
}

func (r *reader) byteAt() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, fmt.Errorf("unexpected EOF at %d", r.pos)
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *reader) varint() (uint64, error) {
	var result uint64
	shift := uint(0)
	for i := 0; i < 10; i++ {
		b, err := r.byteAt()
		if err != nil {
			return 0, err
		}
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, nil
		}
		shift += 7
	}
	return 0, fmt.Errorf("varint overflow at %d", r.pos)
}

// kb records one KoalaBear element and its exact byte extent.
func (r *reader) kb(path string) {
	if r.err != nil {
		return
	}
	start := r.pos
	v, err := r.varint()
	if err != nil {
		r.err = err
		return
	}
	if v >= uint64(kbPrime) {
		r.err = fmt.Errorf("%s: element %d >= p at offset %d", path, v, start)
		return
	}
	r.out = append(r.out, field{path, start, r.pos - start, uint32(v)})
}

func (r *reader) vecLen() int {
	if r.err != nil {
		return 0
	}
	n, err := r.varint()
	if err != nil {
		r.err = err
		return 0
	}
	return int(n)
}

func (r *reader) option() bool {
	if r.err != nil {
		return false
	}
	b, err := r.byteAt()
	if err != nil {
		r.err = err
		return false
	}
	return b == 1
}

func (r *reader) u8() {
	if r.err != nil {
		return
	}
	if _, err := r.byteAt(); err != nil {
		r.err = err
	}
}

func (r *reader) digest(path string) {
	for i := 0; i < 8; i++ {
		r.kb(fmt.Sprintf("%s[%d]", path, i))
	}
}

func (r *reader) ext4(path string) {
	for i := 0; i < 4; i++ {
		r.kb(fmt.Sprintf("%s.c%d", path, i))
	}
}

func (r *reader) merkleCap(path string) {
	n := r.vecLen()
	for i := 0; i < n; i++ {
		r.digest(fmt.Sprintf("%s[%d]", path, i))
	}
}

func (r *reader) ext4Vec(path string) {
	n := r.vecLen()
	for i := 0; i < n; i++ {
		r.ext4(fmt.Sprintf("%s[%d]", path, i))
	}
}

func (r *reader) optExt4Vec(path string) {
	if r.option() {
		r.ext4Vec(path)
	}
}

func (r *reader) digestVec(path string) {
	n := r.vecLen()
	for i := 0; i < n; i++ {
		r.digest(fmt.Sprintf("%s[%d]", path, i))
	}
}

func (r *reader) kbVec(path string) {
	n := r.vecLen()
	for i := 0; i < n; i++ {
		r.kb(fmt.Sprintf("%s[%d]", path, i))
	}
}

// walkProof traverses the postcard proof and returns every KoalaBear element
// with its byte offset. Traversal order mirrors sp1fri/decode.go::decodeProof.
func walkProof(bs []byte) ([]field, error) {
	r := &reader{buf: bs}

	// Commitments
	r.merkleCap("commitments.trace")
	r.merkleCap("commitments.quotient_chunks")
	if r.option() {
		r.merkleCap("commitments.random")
	}

	// OpenedValues
	r.ext4Vec("opened_values.trace_local")
	r.optExt4Vec("opened_values.trace_next")
	r.optExt4Vec("opened_values.preprocessed_local")
	r.optExt4Vec("opened_values.preprocessed_next")
	qn := r.vecLen()
	for i := 0; i < qn; i++ {
		r.ext4Vec(fmt.Sprintf("opened_values.quotient_chunks[%d]", i))
	}
	r.optExt4Vec("opened_values.random")

	// FriProof
	cn := r.vecLen()
	for i := 0; i < cn; i++ {
		r.merkleCap(fmt.Sprintf("opening_proof.commit_phase_commits[%d]", i))
	}
	r.kbVec("opening_proof.commit_pow_witnesses")
	qpn := r.vecLen()
	for q := 0; q < qpn; q++ {
		bn := r.vecLen()
		for b := 0; b < bn; b++ {
			on := r.vecLen()
			for o := 0; o < on; o++ {
				r.kbVec(fmt.Sprintf("opening_proof.query_proofs[%d].input_proof[%d].opened_values[%d]", q, b, o))
			}
			r.digestVec(fmt.Sprintf("opening_proof.query_proofs[%d].input_proof[%d].opening_proof", q, b))
		}
		sn := r.vecLen()
		for s := 0; s < sn; s++ {
			r.u8() // log_arity
			r.ext4Vec(fmt.Sprintf("opening_proof.query_proofs[%d].commit_phase_openings[%d].sibling_values", q, s))
			r.digestVec(fmt.Sprintf("opening_proof.query_proofs[%d].commit_phase_openings[%d].opening_proof", q, s))
		}
	}
	r.ext4Vec("opening_proof.final_poly")
	r.kb("opening_proof.query_pow_witness")
	r.kb("degree_bits")

	if r.err != nil {
		return nil, r.err
	}
	if r.pos != len(bs) {
		return nil, fmt.Errorf("walk ended at %d, want %d (trailing bytes)", r.pos, len(bs))
	}
	return r.out, nil
}

// ---------------------------------------------------------------------------
// README rendering
// ---------------------------------------------------------------------------

type readmeData struct {
	Name       string
	Mutation   string
	Target     string
	Offset     int
	OrigByte   byte
	MutByte    byte
	FieldPath  string
	OrigVal    uint64
	MutVal     uint64
	VarintNote string
	SizeNote   string
	DocPoint   string
	RealPoint  string
	RealErr    string
	Note       string
	Unchanged  string
}

func renderReadme(d readmeData) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — negative fixture\n\n", d.Name)
	fmt.Fprintf(&b, "Generated by `tests/vectors/sp1/fri/corruptions/gen.go` from\n")
	fmt.Fprintf(&b, "`../minimal-guest/`. Do not hand-edit — re-run the generator.\n\n")

	fmt.Fprintf(&b, "## Mutation\n\n%s\n\n", d.Mutation)
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Mutated file | `%s` |\n", d.Target)
	if d.FieldPath != "" {
		fmt.Fprintf(&b, "| Decoded field | `%s` |\n", d.FieldPath)
	}
	if d.OrigByte != d.MutByte || d.Offset != 0 {
		fmt.Fprintf(&b, "| Byte offset | %d (0x%x) |\n", d.Offset, d.Offset)
		fmt.Fprintf(&b, "| Original byte | 0x%02x |\n", d.OrigByte)
		fmt.Fprintf(&b, "| Mutated byte | 0x%02x |\n", d.MutByte)
	}
	if d.OrigVal != d.MutVal {
		fmt.Fprintf(&b, "| Original value | %d |\n", d.OrigVal)
		fmt.Fprintf(&b, "| Mutated value | %d |\n", d.MutVal)
	}
	if d.SizeNote != "" {
		fmt.Fprintf(&b, "| Size | %s |\n", d.SizeNote)
	}
	if d.Unchanged != "" {
		fmt.Fprintf(&b, "| Unchanged copy | `%s` |\n", d.Unchanged)
	}
	b.WriteString("\n")
	if d.VarintNote != "" {
		fmt.Fprintf(&b, "%s.\n\n", d.VarintNote)
	}

	b.WriteString("## Detection point\n\n")
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Documented (docs/sp1-fri-verifier.md §6) | %s |\n", d.DocPoint)
	fmt.Fprintf(&b, "| Actually observed | %s |\n", d.RealPoint)
	b.WriteString("\nRejection message:\n\n```text\n")
	b.WriteString(d.RealErr)
	b.WriteString("\n```\n\n")
	b.WriteString(d.Note)
	b.WriteString("\n\n## Asserted by\n\n")
	b.WriteString("`compilers/go/codegen/sp1_fri_negative_test.go`\n" +
		"(`TestSp1FriVerifier_RejectsCorruptionFixtures`), which re-derives the byte\n" +
		"offset from the real decoder and asserts the exact rejection message above.\n")
	return b.String()
}

const badVkReadme = `# bad_vk — NOT GENERATED

**There is no fixture in this directory, and there cannot be one yet.**

The original corruption matrix specified "use a VK hash from a different guest
program", expecting a ` + "`vk_hash.hex`" + ` alongside the proof. That file does not
exist for ` + "`minimal-guest/`" + `, and a corruption cannot be derived from an input
that has no original.

## Why there is no VK hash to corrupt

` + "`minimal-guest/proof.postcard`" + ` is a raw Plonky3 ` + "`p3_uni_stark::Proof`" + ` — a
Fibonacci AIR proven directly over KoalaBear. It is not wrapped in an SP1
outer proof, so it has no SP1 verifying key and therefore no keccak256 VK
hash. This is not an oversight in the fixture; it is why the validated PoC
parameter set pins

    SP1VKeyHashByteSize: 0

in both ` + "`compilers/go/codegen/sp1_fri.go::DefaultSP1FriParams()`" + ` and
` + "`packages/runar-go/sp1fri/unlocking.go::MinimalGuestParams()`" + `. At that
parameter set the ` + "`sp1VKeyHash`" + ` argument is not pushed by the unlocking
script and is not absorbed into the Fiat-Shamir transcript by the emitted
locking script — the compiler explicitly drops it
(` + "`sp1_fri.go::lowerVerifySP1FRI`" + `, the ` + "`SP1VKeyHashByteSize == 0`" + ` branch).

That drop is now scoped to a zero-length VK field. At ` + "`SP1VKeyHashByteSize > 0`" + `
the verifying key IS absorbed, at the head of the transcript (R-057); see
"What would have to land first" below.

The off-chain reference verifier agrees: ` + "`sp1fri.Verify(proof, publicValues)`" + `
takes no VK hash parameter at all.

**A wrong VK hash therefore cannot change any verifier decision at the PoC
parameter set.** A fixture here would be inert bytes with no test able to
make a meaningful assertion about them, which is worse than an empty
directory.

## What would have to land first

1. A fixture whose proof is a real SP1 outer proof with a verifying key
   (` + "`evm-guest/`" + ` is still a raw Plonky3 proof, not an SP1 wrapper).
2. ~~A parameter set with ` + "`SP1VKeyHashByteSize == 32`" + ` wired end-to-end, so the
   VK hash is actually absorbed into the transcript.~~ **DONE (R-057).**
   ` + "`SP1VKeyHashByteSize > 0`" + ` now absorbs the contract's readonly
   ` + "`Sp1VKeyHash`" + ` property — a LOCKING-script constant, not an unlocking-script
   push — at the head of the Fiat-Shamir transcript per
   ` + "`docs/sp1-fri-verifier.md`" + ` §3. Before R-057 this was dead code:
   ` + "`sp1FriPrePushedFieldNames`" + ` never allocated the ` + "`_obs_sp1_vk_hash`" + ` slot
   that ` + "`emitTranscriptInit`" + ` Step 2b looks up by name, so asking for 32
   panicked the compiler and NO parameter set bound the key. Proven by
   ` + "`compilers/go/compiler.TestSp1FriVerifier_VerifyingKeyBindsTheProgram`" + `:
   the same proof is accepted under one verifying key and rejected under
   another. Only item 1 is still outstanding.

Until both exist, the closest runnable coverage is ` + "`../wrong_program/`" + `, which
binds the minimal-guest proof to a different program's public values — the
only program-identifying input the verifier currently consumes.
`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeFile(path, content string) {
	check(os.WriteFile(path, []byte(content), 0o644))
}

func check(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen: %v\n", err)
		os.Exit(1)
	}
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "gen: "+format+"\n", args...)
	os.Exit(1)
}
