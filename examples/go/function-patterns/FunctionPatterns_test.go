package contract

import (
	"testing"
	runar "github.com/icellan/runar/packages/runar-go"
)

func ownerSig() runar.Sig { return runar.SignTestMessage(runar.Alice.PrivKey) }

func newContract() *FunctionPatterns {
	return &FunctionPatterns{
		Owner:   runar.Alice.PubKey,
		Balance: 10000,
	}
}

// ---------------------------------------------------------------------------
// Public method: Deposit
// ---------------------------------------------------------------------------

func TestDeposit(t *testing.T) {
	c := newContract()
	c.Deposit(ownerSig(), 500)
	if c.Balance != 10500 {
		t.Errorf("expected 10500, got %d", c.Balance)
	}
}

func TestDeposit_Multiple(t *testing.T) {
	c := newContract()
	c.Deposit(ownerSig(), 100)
	c.Deposit(ownerSig(), 200)
	c.Deposit(ownerSig(), 300)
	if c.Balance != 10600 {
		t.Errorf("expected 10600, got %d", c.Balance)
	}
}

func TestDeposit_RejectsZero(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for zero deposit")
		}
	}()
	newContract().Deposit(ownerSig(), 0)
}

func TestDeposit_RejectsNegative(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for negative deposit")
		}
	}()
	newContract().Deposit(ownerSig(), -100)
}

// ---------------------------------------------------------------------------
// Public method: Withdraw (uses private method + built-in)
// ---------------------------------------------------------------------------

func TestWithdraw_NoFee(t *testing.T) {
	c := newContract()
	c.Withdraw(ownerSig(), 3000, 0) // 0 bps = no fee
	if c.Balance != 7000 {
		t.Errorf("expected 7000, got %d", c.Balance)
	}
}

func TestWithdraw_WithFee(t *testing.T) {
	c := newContract()
	// Withdraw 1000 with 500 bps (5%) fee = 50, total deducted = 1050
	c.Withdraw(ownerSig(), 1000, 500)
	if c.Balance != 8950 {
		t.Errorf("expected 8950, got %d", c.Balance)
	}
}

func TestWithdraw_FullBalance(t *testing.T) {
	c := newContract()
	c.Withdraw(ownerSig(), 10000, 0)
	if c.Balance != 0 {
		t.Errorf("expected 0, got %d", c.Balance)
	}
}

func TestWithdraw_InsufficientBalance(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for insufficient balance")
		}
	}()
	newContract().Withdraw(ownerSig(), 20000, 0)
}

func TestWithdraw_FeeExceedsBalance(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when amount+fee exceeds balance")
		}
	}()
	// 10000 balance, withdraw 10000 with 100 bps fee = 100 -> total 10100 > 10000
	newContract().Withdraw(ownerSig(), 10000, 100)
}

// ---------------------------------------------------------------------------
// Public method: Scale (uses standalone helper)
// ---------------------------------------------------------------------------

func TestScale_Double(t *testing.T) {
	c := newContract()
	c.Scale(ownerSig(), 2, 1) // * 2/1 = double
	if c.Balance != 20000 {
		t.Errorf("expected 20000, got %d", c.Balance)
	}
}

func TestScale_Half(t *testing.T) {
	c := newContract()
	c.Scale(ownerSig(), 1, 2) // * 1/2 = half
	if c.Balance != 5000 {
		t.Errorf("expected 5000, got %d", c.Balance)
	}
}

func TestScale_ThreeQuarters(t *testing.T) {
	c := newContract()
	c.Scale(ownerSig(), 3, 4) // * 3/4 = 7500
	if c.Balance != 7500 {
		t.Errorf("expected 7500, got %d", c.Balance)
	}
}

// ---------------------------------------------------------------------------
// Public method: Normalize (uses composed standalone helpers)
// ---------------------------------------------------------------------------

func TestNormalize_ClampsAndRounds(t *testing.T) {
	c := newContract()
	// Balance=10000, clamp to [0, 8000], round down to step=1000 -> 8000
	c.Normalize(ownerSig(), 0, 8000, 1000)
	if c.Balance != 8000 {
		t.Errorf("expected 8000, got %d", c.Balance)
	}
}

func TestNormalize_RoundsDown(t *testing.T) {
	c := &FunctionPatterns{Owner: runar.Alice.PubKey, Balance: 7777}
	// Clamp to [0, 10000] (no effect), round down to step=1000 -> 7000
	c.Normalize(ownerSig(), 0, 10000, 1000)
	if c.Balance != 7000 {
		t.Errorf("expected 7000, got %d", c.Balance)
	}
}

func TestNormalize_ClampsUp(t *testing.T) {
	c := &FunctionPatterns{Owner: runar.Alice.PubKey, Balance: 50}
	// Clamp to [1000, 10000] -> 1000, round down to step=500 -> 1000
	c.Normalize(ownerSig(), 1000, 10000, 500)
	if c.Balance != 1000 {
		t.Errorf("expected 1000, got %d", c.Balance)
	}
}

// ---------------------------------------------------------------------------
// Standalone helpers — unit tests
// ---------------------------------------------------------------------------

func TestIsPositive(t *testing.T) {
	if !isPositive(1) {
		t.Error("expected true for 1")
	}
	if !isPositive(100) {
		t.Error("expected true for 100")
	}
	if isPositive(0) {
		t.Error("expected false for 0")
	}
	if isPositive(-5) {
		t.Error("expected false for -5")
	}
}

func TestScaleValue(t *testing.T) {
	if v := scaleValue(1000, 3, 4); v != 750 {
		t.Errorf("scaleValue(1000, 3, 4) = %d, want 750", v)
	}
	if v := scaleValue(100, 1, 3); v != 33 {
		t.Errorf("scaleValue(100, 1, 3) = %d, want 33", v)
	}
}

func TestClampValue(t *testing.T) {
	if v := clampValue(5, 10, 100); v != 10 {
		t.Errorf("clampValue(5, 10, 100) = %d, want 10", v)
	}
	if v := clampValue(200, 10, 100); v != 100 {
		t.Errorf("clampValue(200, 10, 100) = %d, want 100", v)
	}
	if v := clampValue(50, 10, 100); v != 50 {
		t.Errorf("clampValue(50, 10, 100) = %d, want 50", v)
	}
}

func TestRoundDown(t *testing.T) {
	if v := roundDown(7777, 1000); v != 7000 {
		t.Errorf("roundDown(7777, 1000) = %d, want 7000", v)
	}
	if v := roundDown(5000, 1000); v != 5000 {
		t.Errorf("roundDown(5000, 1000) = %d, want 5000", v)
	}
	if v := roundDown(999, 500); v != 500 {
		t.Errorf("roundDown(999, 500) = %d, want 500", v)
	}
}

// ---------------------------------------------------------------------------
// Composition: multi-step workflows
// ---------------------------------------------------------------------------

func TestDepositThenWithdrawWithFee(t *testing.T) {
	c := newContract()
	c.Deposit(ownerSig(), 5000)    // 10000 + 5000 = 15000
	c.Withdraw(ownerSig(), 5000, 200) // 2% fee = 100, total = 5100 -> 9900
	if c.Balance != 9900 {
		t.Errorf("expected 9900, got %d", c.Balance)
	}
}

func TestScaleThenNormalize(t *testing.T) {
	c := newContract()
	c.Scale(ownerSig(), 3, 4)                   // 10000 * 3/4 = 7500
	c.Normalize(ownerSig(), 0, 10000, 1000) // clamp [0,10000] (no effect), round to 1000 -> 7000
	if c.Balance != 7000 {
		t.Errorf("expected 7000, got %d", c.Balance)
	}
}

// ---------------------------------------------------------------------------
// Rúnar compile check
// ---------------------------------------------------------------------------

func TestFunctionPatterns_Compile(t *testing.T) {
	if err := runar.CompileCheck("FunctionPatterns.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
