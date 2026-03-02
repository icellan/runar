package contract

import "runar"

type MathDemo struct {
	runar.StatefulSmartContract
	Value runar.Bigint
}

func (c *MathDemo) DivideBy(divisor runar.Bigint) {
	c.Value = runar.Safediv(c.Value, divisor)
}

func (c *MathDemo) WithdrawWithFee(amount, feeBps runar.Bigint) {
	fee := runar.PercentOf(amount, feeBps)
	total := amount + fee
	runar.Assert(total <= c.Value)
	c.Value = c.Value - total
}

func (c *MathDemo) ClampValue(lo, hi runar.Bigint) {
	c.Value = runar.Clamp(c.Value, lo, hi)
}

func (c *MathDemo) Normalize() {
	c.Value = runar.Sign(c.Value)
}

func (c *MathDemo) Exponentiate(exp runar.Bigint) {
	c.Value = runar.Pow(c.Value, exp)
}

func (c *MathDemo) SquareRoot() {
	c.Value = runar.Sqrt(c.Value)
}

func (c *MathDemo) ReduceGcd(other runar.Bigint) {
	c.Value = runar.Gcd(c.Value, other)
}

func (c *MathDemo) ScaleByRatio(numerator, denominator runar.Bigint) {
	c.Value = runar.MulDiv(c.Value, numerator, denominator)
}

func (c *MathDemo) ComputeLog2() {
	c.Value = runar.Log2(c.Value)
}
