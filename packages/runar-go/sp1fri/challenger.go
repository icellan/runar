package sp1fri

// DuplexChallenger over Poseidon2-KoalaBear (width=16, rate=8).
//
// Direct port of `challenger/src/duplex_challenger.rs` for the SP1 v6.0.2
// concrete instantiation `DuplexChallenger<KoalaBear, Poseidon2KoalaBear<16>, 16, 8>`.
//
// All field elements are canonical KoalaBear (uint32 in [0, p)).

const (
	challengerWidth = 16
	challengerRate  = 8
)

// DuplexChallenger is the runtime sponge state used for Fiat-Shamir.
type DuplexChallenger struct {
	// SpongeState is `[F; WIDTH]`.
	spongeState [challengerWidth]uint32
	// inputBuffer holds observed values not yet absorbed.
	inputBuffer []uint32
	// outputBuffer holds squeezed values (sample() pops from the back —
	// see `sample`, line 211 of `duplex_challenger.rs`).
	outputBuffer []uint32
}

// NewDuplexChallenger returns a fresh challenger with zeroed state.
func NewDuplexChallenger() *DuplexChallenger {
	return &DuplexChallenger{
		spongeState:  [challengerWidth]uint32{},
		inputBuffer:  make([]uint32, 0, challengerRate),
		outputBuffer: make([]uint32, 0, challengerRate),
	}
}

// duplexing absorbs the input buffer into the sponge state and applies the
// permutation. Mirrors `DuplexChallenger::duplexing`, lines 86-99.
func (c *DuplexChallenger) duplexing() {
	if len(c.inputBuffer) > challengerRate {
		panic("DuplexChallenger.duplexing: input buffer overflow")
	}
	// Overwrite the first `len(input)` rate positions.
	for i, v := range c.inputBuffer {
		c.spongeState[i] = v
	}
	c.inputBuffer = c.inputBuffer[:0]

	Poseidon2Permute(&c.spongeState)

	// outputBuffer = state[..RATE]. Sample() pops from the back.
	c.outputBuffer = c.outputBuffer[:0]
	c.outputBuffer = append(c.outputBuffer, c.spongeState[:challengerRate]...)
}

// Observe absorbs a single canonical KoalaBear element.
//
// Mirrors `CanObserve<F>::observe` (lines 116-125): clears the output
// buffer (any sampled values are now invalid), pushes to input buffer,
// and triggers a duplex when the buffer fills.
func (c *DuplexChallenger) Observe(v uint32) {
	c.outputBuffer = c.outputBuffer[:0]
	c.inputBuffer = append(c.inputBuffer, v)
	if len(c.inputBuffer) == challengerRate {
		c.duplexing()
	}
}

// ObserveSlice absorbs each element in turn.
func (c *DuplexChallenger) ObserveSlice(vs []uint32) {
	for _, v := range vs {
		c.Observe(v)
	}
}

// ObserveDigest absorbs an 8-element Poseidon2 digest.
func (c *DuplexChallenger) ObserveDigest(d [8]uint32) {
	for _, v := range d {
		c.Observe(v)
	}
}

// ObserveExt4 absorbs an extension-field element by its 4 base coefficients
// (matches `FieldChallenger::observe_algebra_element`, lines 102-108 of
// `challenger/src/lib.rs`).
func (c *DuplexChallenger) ObserveExt4(e Ext4) {
	for _, v := range e {
		c.Observe(v)
	}
}

// ObserveExt4Slice absorbs a slice of Ext4 elements.
func (c *DuplexChallenger) ObserveExt4Slice(es []Ext4) {
	for _, e := range es {
		c.ObserveExt4(e)
	}
}

// Sample squeezes one canonical KoalaBear element. Mirrors
// `CanSample<F>::sample` (lines 196-216).
//
// "If we have buffered inputs, we must perform a duplexing so that the
// challenge will reflect them. Or if we've run out of outputs, we must
// perform a duplexing to get more."
func (c *DuplexChallenger) Sample() uint32 {
	if len(c.inputBuffer) > 0 || len(c.outputBuffer) == 0 {
		c.duplexing()
	}
	// Pop from end.
	n := len(c.outputBuffer) - 1
	v := c.outputBuffer[n]
	c.outputBuffer = c.outputBuffer[:n]
	return v
}

// SampleExt4 samples a degree-4 extension element by sampling 4 base coefficients
// in order (matches `sample_algebra_element` building each via
// `from_basis_coefficients_fn` index 0..3).
func (c *DuplexChallenger) SampleExt4() Ext4 {
	var out Ext4
	for i := 0; i < 4; i++ {
		out[i] = c.Sample()
	}
	return out
}

// SampleBits returns the low `bits` bits of a sampled canonical KoalaBear value.
// Mirrors `CanSampleBits::sample_bits` for KoalaBear (lines 232-238).
func (c *DuplexChallenger) SampleBits(bits int) uint64 {
	if bits >= 64 {
		panic("SampleBits: bits >= usize::BITS")
	}
	if uint64(1)<<bits >= uint64(KbPrime) {
		panic("SampleBits: 1 << bits >= field order")
	}
	v := uint64(c.Sample())
	return v & ((uint64(1) << bits) - 1)
}

// CheckWitness verifies a PoW witness. Mirrors `GrindingChallenger::check_witness`
// (lines 40-47 of `challenger/src/grinding_challenger.rs`).
//
//	if bits == 0 { return true }
//	self.observe(witness)
//	self.sample_bits(bits) == 0
func (c *DuplexChallenger) CheckWitness(bits int, witness uint32) bool {
	if bits == 0 {
		return true
	}
	c.Observe(witness)
	return c.SampleBits(bits) == 0
}
