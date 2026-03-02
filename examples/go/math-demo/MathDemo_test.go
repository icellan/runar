package contract

import (
	"testing"
	"runar"
)

func TestMathDemo_Safediv(t *testing.T) {
	c := &MathDemo{Value: 100}
	c.DivideBy(5)
	if c.Value != 20 {
		t.Errorf("expected 20, got %d", c.Value)
	}
}

func TestMathDemo_Safediv_Truncates(t *testing.T) {
	c := &MathDemo{Value: 7}
	c.DivideBy(2)
	if c.Value != 3 {
		t.Errorf("expected 3, got %d", c.Value)
	}
}

func TestMathDemo_Safediv_RejectsDivByZero(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on division by zero")
		}
	}()
	c := &MathDemo{Value: 10}
	c.DivideBy(0)
}

func TestMathDemo_PercentOf(t *testing.T) {
	c := &MathDemo{Value: 10000}
	c.WithdrawWithFee(1000, 500) // 5% fee = 50, total = 1050
	if c.Value != 8950 {
		t.Errorf("expected 8950, got %d", c.Value)
	}
}

func TestMathDemo_Clamp_Below(t *testing.T) {
	c := &MathDemo{Value: 3}
	c.ClampValue(10, 100)
	if c.Value != 10 {
		t.Errorf("expected 10, got %d", c.Value)
	}
}

func TestMathDemo_Clamp_Above(t *testing.T) {
	c := &MathDemo{Value: 200}
	c.ClampValue(10, 100)
	if c.Value != 100 {
		t.Errorf("expected 100, got %d", c.Value)
	}
}

func TestMathDemo_Clamp_InRange(t *testing.T) {
	c := &MathDemo{Value: 50}
	c.ClampValue(10, 100)
	if c.Value != 50 {
		t.Errorf("expected 50, got %d", c.Value)
	}
}

func TestMathDemo_Sign_Positive(t *testing.T) {
	c := &MathDemo{Value: 42}
	c.Normalize()
	if c.Value != 1 {
		t.Errorf("expected 1, got %d", c.Value)
	}
}

func TestMathDemo_Sign_Negative(t *testing.T) {
	c := &MathDemo{Value: -7}
	c.Normalize()
	if c.Value != -1 {
		t.Errorf("expected -1, got %d", c.Value)
	}
}

func TestMathDemo_Sign_Zero(t *testing.T) {
	c := &MathDemo{Value: 0}
	c.Normalize()
	if c.Value != 0 {
		t.Errorf("expected 0, got %d", c.Value)
	}
}

func TestMathDemo_Pow(t *testing.T) {
	c := &MathDemo{Value: 2}
	c.Exponentiate(10)
	if c.Value != 1024 {
		t.Errorf("expected 1024, got %d", c.Value)
	}
}

func TestMathDemo_Pow_Zero(t *testing.T) {
	c := &MathDemo{Value: 99}
	c.Exponentiate(0)
	if c.Value != 1 {
		t.Errorf("expected 1, got %d", c.Value)
	}
}

func TestMathDemo_Sqrt(t *testing.T) {
	c := &MathDemo{Value: 100}
	c.SquareRoot()
	if c.Value != 10 {
		t.Errorf("expected 10, got %d", c.Value)
	}
}

func TestMathDemo_Sqrt_NonPerfect(t *testing.T) {
	c := &MathDemo{Value: 10}
	c.SquareRoot()
	if c.Value != 3 {
		t.Errorf("expected 3, got %d", c.Value)
	}
}

func TestMathDemo_Gcd(t *testing.T) {
	c := &MathDemo{Value: 12}
	c.ReduceGcd(8)
	if c.Value != 4 {
		t.Errorf("expected 4, got %d", c.Value)
	}
}

func TestMathDemo_Gcd_Coprime(t *testing.T) {
	c := &MathDemo{Value: 7}
	c.ReduceGcd(13)
	if c.Value != 1 {
		t.Errorf("expected 1, got %d", c.Value)
	}
}

func TestMathDemo_MulDiv(t *testing.T) {
	c := &MathDemo{Value: 1000}
	c.ScaleByRatio(3, 4)
	if c.Value != 750 {
		t.Errorf("expected 750, got %d", c.Value)
	}
}

func TestMathDemo_Log2(t *testing.T) {
	c := &MathDemo{Value: 1024}
	c.ComputeLog2()
	if c.Value != 10 {
		t.Errorf("expected 10, got %d", c.Value)
	}
}

func TestMathDemo_Compile(t *testing.T) {
	if err := runar.CompileCheck("MathDemo.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
