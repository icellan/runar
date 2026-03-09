// SLH-DSA (FIPS 205) SHA-256 reference implementation.
//
// Implements all 6 SHA-256 parameter sets for key generation, signing, and
// verification. Used by the Rúnar Go SDK for real verification.
//
// Based on FIPS 205 (Stateless Hash-Based Digital Signature Standard).
// Only the SHA2 instantiation (not SHAKE) is implemented.
//
// IMPORTANT: The WOTS+ within SLH-DSA uses FIPS 205's tweakable hash
// T(PK.seed, ADRS, M) with compressed ADRS — this is DIFFERENT from the
// standalone WOTS+ in wots.go which uses a simpler F(pubSeed, chainIdx, stepIdx, M).
package runar

import (
	"crypto/rand"
	"crypto/sha256"
	"math"
)

// ---------------------------------------------------------------------------
// Parameter sets (FIPS 205 Table 1, SHA2 variants only)
// ---------------------------------------------------------------------------

// SLHParams holds the parameters for an SLH-DSA parameter set.
type SLHParams struct {
	Name string
	N    int // Security parameter (hash output bytes): 16, 24, or 32
	H    int // Total tree height
	D    int // Number of hypertree layers
	HP   int // Height of each subtree: H/D
	A    int // FORS tree height
	K    int // Number of FORS trees
	W    int // Winternitz parameter (always 16)
	Len  int // WOTS+ chain count
}

func slhWotsLen(n, w int) int {
	len1 := int(math.Ceil(float64(8*n) / math.Log2(float64(w))))
	len2 := int(math.Floor(math.Log2(float64(len1)*float64(w-1))/math.Log2(float64(w)))) + 1
	return len1 + len2
}

// Pre-defined parameter sets for all 6 SHA-256 variants.
var (
	SLH_SHA2_128s = SLHParams{Name: "SLH-DSA-SHA2-128s", N: 16, H: 63, D: 7, HP: 9, A: 12, K: 14, W: 16, Len: slhWotsLen(16, 16)}
	SLH_SHA2_128f = SLHParams{Name: "SLH-DSA-SHA2-128f", N: 16, H: 66, D: 22, HP: 3, A: 6, K: 33, W: 16, Len: slhWotsLen(16, 16)}
	SLH_SHA2_192s = SLHParams{Name: "SLH-DSA-SHA2-192s", N: 24, H: 63, D: 7, HP: 9, A: 14, K: 17, W: 16, Len: slhWotsLen(24, 16)}
	SLH_SHA2_192f = SLHParams{Name: "SLH-DSA-SHA2-192f", N: 24, H: 66, D: 22, HP: 3, A: 8, K: 33, W: 16, Len: slhWotsLen(24, 16)}
	SLH_SHA2_256s = SLHParams{Name: "SLH-DSA-SHA2-256s", N: 32, H: 64, D: 8, HP: 8, A: 14, K: 22, W: 16, Len: slhWotsLen(32, 16)}
	SLH_SHA2_256f = SLHParams{Name: "SLH-DSA-SHA2-256f", N: 32, H: 68, D: 17, HP: 4, A: 8, K: 35, W: 16, Len: slhWotsLen(32, 16)}
)

// AllSHA2Params contains all 6 SHA-256 parameter sets.
var AllSHA2Params = []SLHParams{
	SLH_SHA2_128s, SLH_SHA2_128f,
	SLH_SHA2_192s, SLH_SHA2_192f,
	SLH_SHA2_256s, SLH_SHA2_256f,
}

// ---------------------------------------------------------------------------
// ADRS (Address) — 32-byte domain separator (FIPS 205 Section 4.2)
// ---------------------------------------------------------------------------

const slhADRSSize = 32

// Address types.
const (
	slhADRS_WOTS_HASH = 0
	slhADRS_WOTS_PK   = 1
	slhADRS_TREE      = 2
	slhADRS_FORS_TREE = 3
	slhADRS_FORS_ROOTS = 4
	slhADRS_WOTS_PRF  = 5
	slhADRS_FORS_PRF  = 6
)

func slhNewADRS() []byte {
	return make([]byte, slhADRSSize)
}

func slhSetLayerAddress(adrs []byte, layer int) {
	adrs[0] = byte((layer >> 24) & 0xff)
	adrs[1] = byte((layer >> 16) & 0xff)
	adrs[2] = byte((layer >> 8) & 0xff)
	adrs[3] = byte(layer & 0xff)
}

func slhSetTreeAddress(adrs []byte, tree uint64) {
	// Bytes 4-15 (12 bytes for tree address)
	for i := 0; i < 12; i++ {
		adrs[4+11-i] = byte((tree >> uint(8*i)) & 0xff)
	}
}

func slhSetType(adrs []byte, typ int) {
	// Byte 16-19: type (big-endian u32), also zeroes bytes 20-31
	adrs[16] = byte((typ >> 24) & 0xff)
	adrs[17] = byte((typ >> 16) & 0xff)
	adrs[18] = byte((typ >> 8) & 0xff)
	adrs[19] = byte(typ & 0xff)
	for i := 20; i < 32; i++ {
		adrs[i] = 0
	}
}

func slhSetKeyPairAddress(adrs []byte, kp int) {
	adrs[20] = byte((kp >> 24) & 0xff)
	adrs[21] = byte((kp >> 16) & 0xff)
	adrs[22] = byte((kp >> 8) & 0xff)
	adrs[23] = byte(kp & 0xff)
}

func slhSetChainAddress(adrs []byte, chain int) {
	adrs[24] = byte((chain >> 24) & 0xff)
	adrs[25] = byte((chain >> 16) & 0xff)
	adrs[26] = byte((chain >> 8) & 0xff)
	adrs[27] = byte(chain & 0xff)
}

func slhSetHashAddress(adrs []byte, hash int) {
	adrs[28] = byte((hash >> 24) & 0xff)
	adrs[29] = byte((hash >> 16) & 0xff)
	adrs[30] = byte((hash >> 8) & 0xff)
	adrs[31] = byte(hash & 0xff)
}

func slhSetTreeHeight(adrs []byte, height int) {
	// Uses same bytes as chain address (24-27)
	slhSetChainAddress(adrs, height)
}

func slhSetTreeIndex(adrs []byte, index int) {
	// Uses same bytes as hash address (28-31)
	slhSetHashAddress(adrs, index)
}

func slhGetKeyPairAddress(adrs []byte) int {
	return (int(adrs[20]) << 24) | (int(adrs[21]) << 16) | (int(adrs[22]) << 8) | int(adrs[23])
}

// compressADRS returns the SHA2 compressed address (22 bytes): drop bytes 3..6.
func slhCompressADRS(adrs []byte) []byte {
	c := make([]byte, 22)
	c[0] = adrs[3] // layer (1 byte)
	// tree address bytes 8-15 (8 bytes)
	copy(c[1:9], adrs[8:16])
	// type (1 byte)
	c[9] = adrs[19]
	// bytes 20-31 (12 bytes)
	copy(c[10:22], adrs[20:32])
	return c
}

// ---------------------------------------------------------------------------
// Hash functions (FIPS 205 Section 11.1 — SHA2 instantiation)
// ---------------------------------------------------------------------------

func slhSha256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func slhConcat(arrays ...[]byte) []byte {
	total := 0
	for _, a := range arrays {
		total += len(a)
	}
	result := make([]byte, total)
	offset := 0
	for _, a := range arrays {
		copy(result[offset:], a)
		offset += len(a)
	}
	return result
}

func slhTrunc(data []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, data[:n])
	return out
}

func slhToByte(value int, n int) []byte {
	b := make([]byte, n)
	v := value
	for i := n - 1; i >= 0 && v > 0; i-- {
		b[i] = byte(v & 0xff)
		v >>= 8
	}
	return b
}

// slhT is the tweakable hash: T_l(PK.seed, ADRS, M) = trunc_n(SHA-256(PK.seed || pad || ADRSc || M))
func slhT(pkSeed, adrs, msg []byte, n int) []byte {
	adrsC := slhCompressADRS(adrs)
	pad := make([]byte, 64-n) // zero padding to fill SHA-256 block
	input := slhConcat(pkSeed, pad, adrsC, msg)
	return slhTrunc(slhSha256(input), n)
}

// slhPRF computes PRF(PK.seed, SK.seed, ADRS) = trunc_n(SHA-256(PK.seed || pad || ADRSc || SK.seed))
func slhPRF(pkSeed, skSeed, adrs []byte, n int) []byte {
	return slhT(pkSeed, adrs, skSeed, n)
}

// slhPRFmsg computes the randomized message hash PRF.
func slhPRFmsg(skPrf, optRand, msg []byte, n int) []byte {
	pad := make([]byte, 64-n)
	input := slhConcat(pad, skPrf, optRand, msg)
	return slhTrunc(slhSha256(input), n)
}

// slhHmsg hashes a message to get FORS + tree indices using MGF1-SHA-256.
func slhHmsg(R, pkSeed, pkRoot, msg []byte, outLen int) []byte {
	seed := slhConcat(R, pkSeed, pkRoot, msg)
	hash := slhSha256(seed)
	result := make([]byte, outLen)
	offset := 0
	counter := 0
	for offset < outLen {
		block := slhSha256(slhConcat(hash, slhToByte(counter, 4)))
		copyLen := 32
		if outLen-offset < copyLen {
			copyLen = outLen - offset
		}
		copy(result[offset:], block[:copyLen])
		offset += copyLen
		counter++
	}
	return result
}

// ---------------------------------------------------------------------------
// WOTS+ (FIPS 205 Section 5) — SLH-DSA variant with tweakable hash
// ---------------------------------------------------------------------------

func slhWotsChain(x []byte, start, steps int, pkSeed, adrs []byte, n int) []byte {
	tmp := make([]byte, len(x))
	copy(tmp, x)
	for j := start; j < start+steps; j++ {
		slhSetHashAddress(adrs, j)
		tmp = slhT(pkSeed, adrs, tmp, n)
	}
	return tmp
}

func slhWotsLen1(n, w int) int {
	return int(math.Ceil(float64(8*n) / math.Log2(float64(w))))
}

func slhWotsLen2(n, w int) int {
	l1 := slhWotsLen1(n, w)
	return int(math.Floor(math.Log2(float64(l1)*float64(w-1))/math.Log2(float64(w)))) + 1
}

func slhBaseW(msg []byte, w, outLen int) []int {
	logW := int(math.Log2(float64(w)))
	bits := make([]int, 0, len(msg)*8/logW)
	for _, b := range msg {
		for j := 8 - logW; j >= 0; j -= logW {
			bits = append(bits, (int(b)>>j)&(w-1))
		}
	}
	if len(bits) > outLen {
		return bits[:outLen]
	}
	return bits
}

func slhWotsPkFromSig(sig, msg, pkSeed, adrs []byte, params SLHParams) []byte {
	n := params.N
	w := params.W
	l := params.Len
	l1 := slhWotsLen1(n, w)
	l2 := slhWotsLen2(n, w)

	msgDigits := slhBaseW(msg, w, l1)

	// Compute checksum
	csum := 0
	for _, d := range msgDigits {
		csum += (w - 1) - d
	}
	logW := math.Log2(float64(w))
	csumBits := l2 * int(logW)
	shiftAmount := 8 - (csumBits % 8)
	if shiftAmount == 8 {
		shiftAmount = 0
	}
	csumBytes := slhToByte(csum<<shiftAmount, int(math.Ceil(float64(csumBits)/8.0)))
	csumDigits := slhBaseW(csumBytes, w, l2)

	allDigits := make([]int, 0, l1+l2)
	allDigits = append(allDigits, msgDigits...)
	allDigits = append(allDigits, csumDigits...)

	kpAddr := slhGetKeyPairAddress(adrs)
	tmpAdrs := make([]byte, slhADRSSize)
	copy(tmpAdrs, adrs)
	slhSetType(tmpAdrs, slhADRS_WOTS_HASH) // Note: setType zeros bytes 20-31
	slhSetKeyPairAddress(tmpAdrs, kpAddr)   // Restore keypair address

	parts := make([][]byte, l)
	for i := 0; i < l; i++ {
		slhSetChainAddress(tmpAdrs, i)
		sigI := sig[i*n : (i+1)*n]
		parts[i] = slhWotsChain(sigI, allDigits[i], w-1-allDigits[i], pkSeed, tmpAdrs, n)
	}

	// Compress: T_len(PK.seed, ADRS_pk, pk_0 || pk_1 || ... || pk_{len-1})
	pkAdrs := make([]byte, slhADRSSize)
	copy(pkAdrs, adrs)
	slhSetType(pkAdrs, slhADRS_WOTS_PK)
	return slhT(pkSeed, pkAdrs, slhConcat(parts...), n)
}

func slhWotsSign(msg, skSeed, pkSeed, adrs []byte, params SLHParams) []byte {
	n := params.N
	w := params.W
	l := params.Len
	l1 := slhWotsLen1(n, w)
	l2 := slhWotsLen2(n, w)

	msgDigits := slhBaseW(msg, w, l1)
	csum := 0
	for _, d := range msgDigits {
		csum += (w - 1) - d
	}
	logW := math.Log2(float64(w))
	csumBits := l2 * int(logW)
	shiftAmount := 8 - (csumBits % 8)
	if shiftAmount == 8 {
		shiftAmount = 0
	}
	csumBytes := slhToByte(csum<<shiftAmount, int(math.Ceil(float64(csumBits)/8.0)))
	csumDigits := slhBaseW(csumBytes, w, l2)

	allDigits := make([]int, 0, l1+l2)
	allDigits = append(allDigits, msgDigits...)
	allDigits = append(allDigits, csumDigits...)

	sigParts := make([][]byte, l)
	for i := 0; i < l; i++ {
		skAdrs := make([]byte, slhADRSSize)
		copy(skAdrs, adrs)
		slhSetType(skAdrs, slhADRS_WOTS_PRF)
		slhSetKeyPairAddress(skAdrs, slhGetKeyPairAddress(adrs))
		slhSetChainAddress(skAdrs, i)
		slhSetHashAddress(skAdrs, 0)
		sk := slhPRF(pkSeed, skSeed, skAdrs, n)

		chainAdrs := make([]byte, slhADRSSize)
		copy(chainAdrs, adrs)
		slhSetType(chainAdrs, slhADRS_WOTS_HASH)
		slhSetKeyPairAddress(chainAdrs, slhGetKeyPairAddress(adrs))
		slhSetChainAddress(chainAdrs, i)
		sigParts[i] = slhWotsChain(sk, 0, allDigits[i], pkSeed, chainAdrs, n)
	}
	return slhConcat(sigParts...)
}

func slhWotsPk(skSeed, pkSeed, adrs []byte, params SLHParams) []byte {
	n := params.N
	w := params.W
	l := params.Len

	parts := make([][]byte, l)
	for i := 0; i < l; i++ {
		skAdrs := make([]byte, slhADRSSize)
		copy(skAdrs, adrs)
		slhSetType(skAdrs, slhADRS_WOTS_PRF)
		slhSetKeyPairAddress(skAdrs, slhGetKeyPairAddress(adrs))
		slhSetChainAddress(skAdrs, i)
		slhSetHashAddress(skAdrs, 0)
		sk := slhPRF(pkSeed, skSeed, skAdrs, n)

		chainAdrs := make([]byte, slhADRSSize)
		copy(chainAdrs, adrs)
		slhSetType(chainAdrs, slhADRS_WOTS_HASH)
		slhSetKeyPairAddress(chainAdrs, slhGetKeyPairAddress(adrs))
		slhSetChainAddress(chainAdrs, i)
		parts[i] = slhWotsChain(sk, 0, w-1, pkSeed, chainAdrs, n)
	}

	pkAdrs := make([]byte, slhADRSSize)
	copy(pkAdrs, adrs)
	slhSetType(pkAdrs, slhADRS_WOTS_PK)
	return slhT(pkSeed, pkAdrs, slhConcat(parts...), n)
}

// ---------------------------------------------------------------------------
// XMSS (FIPS 205 Section 6) — Merkle tree with WOTS+ leaves
// ---------------------------------------------------------------------------

func slhXmssNode(skSeed, pkSeed []byte, idx, height int, adrs []byte, params SLHParams) []byte {
	n := params.N

	if height == 0 {
		// Leaf: WOTS+ public key
		leafAdrs := make([]byte, slhADRSSize)
		copy(leafAdrs, adrs)
		slhSetType(leafAdrs, slhADRS_WOTS_HASH)
		slhSetKeyPairAddress(leafAdrs, idx)
		return slhWotsPk(skSeed, pkSeed, leafAdrs, params)
	}

	left := slhXmssNode(skSeed, pkSeed, 2*idx, height-1, adrs, params)
	right := slhXmssNode(skSeed, pkSeed, 2*idx+1, height-1, adrs, params)

	nodeAdrs := make([]byte, slhADRSSize)
	copy(nodeAdrs, adrs)
	slhSetType(nodeAdrs, slhADRS_TREE)
	slhSetTreeHeight(nodeAdrs, height)
	slhSetTreeIndex(nodeAdrs, idx)
	return slhT(pkSeed, nodeAdrs, slhConcat(left, right), n)
}

func slhXmssSign(msg, skSeed, pkSeed []byte, idx int, adrs []byte, params SLHParams) []byte {
	hp := params.HP

	// WOTS+ signature
	sigAdrs := make([]byte, slhADRSSize)
	copy(sigAdrs, adrs)
	slhSetType(sigAdrs, slhADRS_WOTS_HASH)
	slhSetKeyPairAddress(sigAdrs, idx)
	sig := slhWotsSign(msg, skSeed, pkSeed, sigAdrs, params)

	// Authentication path
	authParts := make([][]byte, hp)
	for j := 0; j < hp; j++ {
		sibling := (idx >> uint(j)) ^ 1
		authParts[j] = slhXmssNode(skSeed, pkSeed, sibling, j, adrs, params)
	}

	return slhConcat(append([][]byte{sig}, authParts...)...)
}

func slhXmssPkFromSig(idx int, sigXmss, msg, pkSeed, adrs []byte, params SLHParams) []byte {
	n := params.N
	hp := params.HP
	l := params.Len
	wotsSigLen := l * n
	wotsSig := sigXmss[:wotsSigLen]
	auth := sigXmss[wotsSigLen:]

	// Reconstruct WOTS+ public key from signature
	wAdrs := make([]byte, slhADRSSize)
	copy(wAdrs, adrs)
	slhSetType(wAdrs, slhADRS_WOTS_HASH)
	slhSetKeyPairAddress(wAdrs, idx)
	node := slhWotsPkFromSig(wotsSig, msg, pkSeed, wAdrs, params)

	// Walk the authentication path up the Merkle tree
	treeAdrs := make([]byte, slhADRSSize)
	copy(treeAdrs, adrs)
	slhSetType(treeAdrs, slhADRS_TREE)
	for j := 0; j < hp; j++ {
		authJ := auth[j*n : (j+1)*n]
		slhSetTreeHeight(treeAdrs, j+1)
		if ((idx >> uint(j)) & 1) == 0 {
			slhSetTreeIndex(treeAdrs, idx>>(uint(j)+1))
			node = slhT(pkSeed, treeAdrs, slhConcat(node, authJ), n)
		} else {
			slhSetTreeIndex(treeAdrs, idx>>(uint(j)+1))
			node = slhT(pkSeed, treeAdrs, slhConcat(authJ, node), n)
		}
	}
	return node
}

// ---------------------------------------------------------------------------
// FORS (FIPS 205 Section 8) — Forest of random subsets
// ---------------------------------------------------------------------------

func slhForsSign(md, skSeed, pkSeed, adrs []byte, params SLHParams) []byte {
	n := params.N
	a := params.A
	k := params.K

	parts := make([][]byte, 0, k*(1+a))

	for i := 0; i < k; i++ {
		idx := slhExtractForsIdx(md, i, a)

		// Secret value
		skAdrs := make([]byte, slhADRSSize)
		copy(skAdrs, adrs)
		slhSetType(skAdrs, slhADRS_FORS_PRF)
		slhSetKeyPairAddress(skAdrs, slhGetKeyPairAddress(adrs))
		slhSetTreeHeight(skAdrs, 0)
		slhSetTreeIndex(skAdrs, i*(1<<uint(a))+idx)
		sk := slhPRF(pkSeed, skSeed, skAdrs, n)
		parts = append(parts, sk)

		// Authentication path: sibling nodes at each height
		for j := 0; j < a; j++ {
			siblingIdx := (idx >> uint(j)) ^ 1
			parts = append(parts, slhForsNode(skSeed, pkSeed, siblingIdx, j, adrs, i, params))
		}
	}

	return slhConcat(parts...)
}

func slhForsNode(skSeed, pkSeed []byte, idx, height int, adrs []byte, treeIdx int, params SLHParams) []byte {
	n := params.N
	a := params.A

	if height == 0 {
		skAdrs := make([]byte, slhADRSSize)
		copy(skAdrs, adrs)
		slhSetType(skAdrs, slhADRS_FORS_PRF)
		slhSetKeyPairAddress(skAdrs, slhGetKeyPairAddress(adrs))
		slhSetTreeHeight(skAdrs, 0)
		slhSetTreeIndex(skAdrs, treeIdx*(1<<uint(a))+idx)
		sk := slhPRF(pkSeed, skSeed, skAdrs, n)

		leafAdrs := make([]byte, slhADRSSize)
		copy(leafAdrs, adrs)
		slhSetType(leafAdrs, slhADRS_FORS_TREE)
		slhSetKeyPairAddress(leafAdrs, slhGetKeyPairAddress(adrs))
		slhSetTreeHeight(leafAdrs, 0)
		slhSetTreeIndex(leafAdrs, treeIdx*(1<<uint(a))+idx)
		return slhT(pkSeed, leafAdrs, sk, n)
	}

	left := slhForsNode(skSeed, pkSeed, 2*idx, height-1, adrs, treeIdx, params)
	right := slhForsNode(skSeed, pkSeed, 2*idx+1, height-1, adrs, treeIdx, params)

	nodeAdrs := make([]byte, slhADRSSize)
	copy(nodeAdrs, adrs)
	slhSetType(nodeAdrs, slhADRS_FORS_TREE)
	slhSetKeyPairAddress(nodeAdrs, slhGetKeyPairAddress(adrs))
	slhSetTreeHeight(nodeAdrs, height)
	slhSetTreeIndex(nodeAdrs, treeIdx*(1<<uint(a-height))+idx)
	return slhT(pkSeed, nodeAdrs, slhConcat(left, right), n)
}

func slhForsPkFromSig(forsSig, md, pkSeed, adrs []byte, params SLHParams) []byte {
	n := params.N
	a := params.A
	k := params.K
	roots := make([][]byte, k)
	offset := 0

	for i := 0; i < k; i++ {
		idx := slhExtractForsIdx(md, i, a)

		// Secret value -> leaf
		sk := forsSig[offset : offset+n]
		offset += n

		leafAdrs := make([]byte, slhADRSSize)
		copy(leafAdrs, adrs)
		slhSetType(leafAdrs, slhADRS_FORS_TREE)
		slhSetKeyPairAddress(leafAdrs, slhGetKeyPairAddress(adrs))
		slhSetTreeHeight(leafAdrs, 0)
		slhSetTreeIndex(leafAdrs, i*(1<<uint(a))+idx)
		node := slhT(pkSeed, leafAdrs, sk, n)

		// Walk auth path
		authAdrs := make([]byte, slhADRSSize)
		copy(authAdrs, adrs)
		slhSetType(authAdrs, slhADRS_FORS_TREE)
		slhSetKeyPairAddress(authAdrs, slhGetKeyPairAddress(adrs))

		for j := 0; j < a; j++ {
			authJ := forsSig[offset : offset+n]
			offset += n

			slhSetTreeHeight(authAdrs, j+1)
			if ((idx >> uint(j)) & 1) == 0 {
				slhSetTreeIndex(authAdrs, (i*(1<<uint(a-j-1)))+(idx>>(uint(j)+1)))
				node = slhT(pkSeed, authAdrs, slhConcat(node, authJ), n)
			} else {
				slhSetTreeIndex(authAdrs, (i*(1<<uint(a-j-1)))+(idx>>(uint(j)+1)))
				node = slhT(pkSeed, authAdrs, slhConcat(authJ, node), n)
			}
		}
		roots[i] = node
	}

	// Compress FORS roots into public key
	forsPkAdrs := make([]byte, slhADRSSize)
	copy(forsPkAdrs, adrs)
	slhSetType(forsPkAdrs, slhADRS_FORS_ROOTS)
	slhSetKeyPairAddress(forsPkAdrs, slhGetKeyPairAddress(adrs))
	return slhT(pkSeed, forsPkAdrs, slhConcat(roots...), n)
}

func slhExtractForsIdx(md []byte, treeIdx, a int) int {
	bitStart := treeIdx * a
	byteStart := bitStart / 8
	bitOffset := bitStart % 8

	value := 0
	bitsNeeded := a
	bitsRead := 0

	for i := byteStart; bitsRead < bitsNeeded; i++ {
		b := byte(0)
		if i < len(md) {
			b = md[i]
		}
		availBits := 8
		if i == byteStart {
			availBits = 8 - bitOffset
		}
		bitsToTake := availBits
		if bitsNeeded-bitsRead < bitsToTake {
			bitsToTake = bitsNeeded - bitsRead
		}
		shift := 8 - bitsToTake
		if i == byteStart {
			shift = availBits - bitsToTake
		}
		mask := (1 << bitsToTake) - 1
		value = (value << bitsToTake) | ((int(b) >> shift) & mask)
		bitsRead += bitsToTake
	}

	return value
}

// ---------------------------------------------------------------------------
// Top-level: keygen, sign, verify (FIPS 205 Sections 9-10)
// ---------------------------------------------------------------------------

// SLHKeyPair holds an SLH-DSA keypair.
type SLHKeyPair struct {
	SK []byte // SK.seed || SK.prf || PK.seed || PK.root
	PK []byte // PK.seed || PK.root
}

// SLHKeygen generates an SLH-DSA keypair.
// If seed is nil, random bytes are generated. Seed must be 3*params.N bytes.
func SLHKeygen(params SLHParams, seed []byte) SLHKeyPair {
	n := params.N
	s := seed
	if s == nil {
		s = make([]byte, 3*n)
		rand.Read(s)
	}

	skSeed := s[0:n]
	skPrf := s[n : 2*n]
	pkSeed := s[2*n : 3*n]

	// Compute root of the top XMSS tree
	adrs := slhNewADRS()
	slhSetLayerAddress(adrs, params.D-1)
	root := slhXmssNode(skSeed, pkSeed, 0, params.HP, adrs, params)

	sk := slhConcat(skSeed, skPrf, pkSeed, root)
	pk := slhConcat(pkSeed, root)
	return SLHKeyPair{SK: sk, PK: pk}
}

// SLHSign signs a message with SLH-DSA.
func SLHSign(params SLHParams, msg, sk []byte) []byte {
	n := params.N
	d := params.D
	hp := params.HP
	k := params.K
	a := params.A

	skSeed := sk[0:n]
	skPrf := sk[n : 2*n]
	pkSeed := sk[2*n : 3*n]
	pkRoot := sk[3*n : 4*n]

	// Randomize (deterministic for now: optRand = pkSeed)
	optRand := pkSeed
	R := slhPRFmsg(skPrf, optRand, msg, n)

	// Compute message digest
	mdLen := int(math.Ceil(float64(k*a) / 8.0))
	treeIdxLen := int(math.Ceil(float64(params.H-hp) / 8.0))
	leafIdxLen := int(math.Ceil(float64(hp) / 8.0))
	digestLen := mdLen + treeIdxLen + leafIdxLen
	digest := slhHmsg(R, pkSeed, pkRoot, msg, digestLen)

	md := digest[:mdLen]
	var treeIdx uint64
	for i := 0; i < treeIdxLen; i++ {
		treeIdx = (treeIdx << 8) | uint64(digest[mdLen+i])
	}
	treeIdx &= (1 << uint(params.H-hp)) - 1

	leafIdx := 0
	for i := 0; i < leafIdxLen; i++ {
		leafIdx = (leafIdx << 8) | int(digest[mdLen+treeIdxLen+i])
	}
	leafIdx &= (1 << uint(hp)) - 1

	// FORS signature
	forsAdrs := slhNewADRS()
	slhSetTreeAddress(forsAdrs, treeIdx)
	slhSetType(forsAdrs, slhADRS_FORS_TREE)
	slhSetKeyPairAddress(forsAdrs, leafIdx)
	forsSig := slhForsSign(md, skSeed, pkSeed, forsAdrs, params)

	// Get FORS public key to sign with hypertree
	forsPk := slhForsPkFromSig(forsSig, md, pkSeed, forsAdrs, params)

	// Hypertree signature
	htSigParts := make([][]byte, 0, d)
	currentMsg := forsPk
	currentTreeIdx := treeIdx
	currentLeafIdx := leafIdx

	for layer := 0; layer < d; layer++ {
		layerAdrs := slhNewADRS()
		slhSetLayerAddress(layerAdrs, layer)
		slhSetTreeAddress(layerAdrs, currentTreeIdx)

		xmssSig := slhXmssSign(currentMsg, skSeed, pkSeed, currentLeafIdx, layerAdrs, params)
		htSigParts = append(htSigParts, xmssSig)

		// Move to next layer
		currentMsg = slhXmssPkFromSig(currentLeafIdx, xmssSig, currentMsg, pkSeed, layerAdrs, params)
		currentLeafIdx = int(currentTreeIdx & uint64((1<<uint(hp))-1))
		currentTreeIdx = currentTreeIdx >> uint(hp)
	}

	return slhConcat(append([][]byte{R, forsSig}, htSigParts...)...)
}

// SLHVerify verifies an SLH-DSA signature.
func SLHVerify(params SLHParams, msg, sig, pk []byte) bool {
	n := params.N
	d := params.D
	hp := params.HP
	k := params.K
	a := params.A
	l := params.Len

	if len(pk) != 2*n {
		return false
	}
	pkSeed := pk[:n]
	pkRoot := pk[n : 2*n]

	// Parse signature
	offset := 0
	if len(sig) < n {
		return false
	}
	R := sig[offset : offset+n]
	offset += n
	forsSigLen := k * (1 + a) * n
	if len(sig) < offset+forsSigLen {
		return false
	}
	forsSig := sig[offset : offset+forsSigLen]
	offset += forsSigLen

	// Compute message digest
	mdLen := int(math.Ceil(float64(k*a) / 8.0))
	treeIdxLen := int(math.Ceil(float64(params.H-hp) / 8.0))
	leafIdxLen := int(math.Ceil(float64(hp) / 8.0))
	digestLen := mdLen + treeIdxLen + leafIdxLen
	digest := slhHmsg(R, pkSeed, pkRoot, msg, digestLen)

	md := digest[:mdLen]
	var treeIdx uint64
	for i := 0; i < treeIdxLen; i++ {
		treeIdx = (treeIdx << 8) | uint64(digest[mdLen+i])
	}
	treeIdx &= (1 << uint(params.H-hp)) - 1

	leafIdx := 0
	for i := 0; i < leafIdxLen; i++ {
		leafIdx = (leafIdx << 8) | int(digest[mdLen+treeIdxLen+i])
	}
	leafIdx &= (1 << uint(hp)) - 1

	// Verify FORS
	forsAdrs := slhNewADRS()
	slhSetTreeAddress(forsAdrs, treeIdx)
	slhSetType(forsAdrs, slhADRS_FORS_TREE)
	slhSetKeyPairAddress(forsAdrs, leafIdx)
	currentMsg := slhForsPkFromSig(forsSig, md, pkSeed, forsAdrs, params)

	// Verify hypertree
	currentTreeIdx := treeIdx
	currentLeafIdx := leafIdx

	xmssSigLen := (l + hp) * n
	for layer := 0; layer < d; layer++ {
		if len(sig) < offset+xmssSigLen {
			return false
		}
		xmssSig := sig[offset : offset+xmssSigLen]
		offset += xmssSigLen

		layerAdrs := slhNewADRS()
		slhSetLayerAddress(layerAdrs, layer)
		slhSetTreeAddress(layerAdrs, currentTreeIdx)

		currentMsg = slhXmssPkFromSig(currentLeafIdx, xmssSig, currentMsg, pkSeed, layerAdrs, params)
		currentLeafIdx = int(currentTreeIdx & uint64((1<<uint(hp))-1))
		currentTreeIdx = currentTreeIdx >> uint(hp)
	}

	// Compare computed root to PK.root
	if len(currentMsg) != len(pkRoot) {
		return false
	}
	for i := range pkRoot {
		if currentMsg[i] != pkRoot[i] {
			return false
		}
	}
	return true
}
