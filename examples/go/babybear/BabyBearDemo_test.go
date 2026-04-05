package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

// Baby Bear field prime: p = 2^31 - 2^27 + 1 = 2013265921
const bbP int64 = 2013265921

// ---------------------------------------------------------------------------
// checkAdd (bbFieldAdd)
// ---------------------------------------------------------------------------

func TestBabyBearDemo_CheckAdd_Small(t *testing.T) {
	c := &BabyBearDemo{}
	c.CheckAdd(5, 7, 12)
}

func TestBabyBearDemo_CheckAdd_Wrap(t *testing.T) {
	c := &BabyBearDemo{}
	// (p-1) + 1 wraps to 0
	c.CheckAdd(bbP-1, 1, 0)
}

func TestBabyBearDemo_CheckAdd_Zero(t *testing.T) {
	c := &BabyBearDemo{}
	c.CheckAdd(42, 0, 42)
}

func TestBabyBearDemo_CheckAdd_Wrong(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong add result")
		}
	}()

	c := &BabyBearDemo{}
	c.CheckAdd(5, 7, 13)
}

// ---------------------------------------------------------------------------
// checkSub (bbFieldSub)
// ---------------------------------------------------------------------------

func TestBabyBearDemo_CheckSub(t *testing.T) {
	c := &BabyBearDemo{}
	c.CheckSub(10, 3, 7)
}

func TestBabyBearDemo_CheckSub_Wrap(t *testing.T) {
	c := &BabyBearDemo{}
	// 0 - 1 = p - 1
	c.CheckSub(0, 1, bbP-1)
}

func TestBabyBearDemo_CheckSub_Wrong(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong sub result")
		}
	}()

	c := &BabyBearDemo{}
	c.CheckSub(10, 3, 8)
}

// ---------------------------------------------------------------------------
// checkMul (bbFieldMul)
// ---------------------------------------------------------------------------

func TestBabyBearDemo_CheckMul(t *testing.T) {
	c := &BabyBearDemo{}
	c.CheckMul(6, 7, 42)
}

func TestBabyBearDemo_CheckMul_LargeWrap(t *testing.T) {
	c := &BabyBearDemo{}
	// (p-1) * 2 mod p = p - 2
	c.CheckMul(bbP-1, 2, bbP-2)
}

func TestBabyBearDemo_CheckMul_Zero(t *testing.T) {
	c := &BabyBearDemo{}
	c.CheckMul(12345, 0, 0)
}

func TestBabyBearDemo_CheckMul_Wrong(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for wrong mul result")
		}
	}()

	c := &BabyBearDemo{}
	c.CheckMul(6, 7, 43)
}

// ---------------------------------------------------------------------------
// checkInv (bbFieldInv)
// ---------------------------------------------------------------------------

func TestBabyBearDemo_CheckInv_One(t *testing.T) {
	c := &BabyBearDemo{}
	c.CheckInv(1) // inv(1) = 1
}

func TestBabyBearDemo_CheckInv_Two(t *testing.T) {
	c := &BabyBearDemo{}
	c.CheckInv(2)
}

func TestBabyBearDemo_CheckInv_Large(t *testing.T) {
	c := &BabyBearDemo{}
	c.CheckInv(1000000007)
}

// ---------------------------------------------------------------------------
// checkAddSubRoundtrip
// ---------------------------------------------------------------------------

func TestBabyBearDemo_CheckAddSubRoundtrip(t *testing.T) {
	c := &BabyBearDemo{}
	c.CheckAddSubRoundtrip(42, 99)
}

// ---------------------------------------------------------------------------
// checkDistributive
// ---------------------------------------------------------------------------

func TestBabyBearDemo_CheckDistributive(t *testing.T) {
	c := &BabyBearDemo{}
	c.CheckDistributive(5, 7, 11)
}

// ---------------------------------------------------------------------------
// Compile check
// ---------------------------------------------------------------------------

func TestBabyBearDemo_Compile(t *testing.T) {
	if err := runar.CompileCheck("BabyBearDemo.runar.go"); err != nil {
		t.Fatalf("Runar compile check failed: %v", err)
	}
}
