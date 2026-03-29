package contract

import "runar"

type FunctionPatterns struct {
	runar.StatefulSmartContract
	Owner   runar.PubKey `runar:"readonly"`
	Balance runar.Bigint
}

func (c *FunctionPatterns) Deposit(sig runar.Sig, amount runar.Bigint) {
	c.requireOwner(sig)
	runar.Assert(amount > 0)
	c.Balance = c.Balance + amount
}

func (c *FunctionPatterns) Withdraw(sig runar.Sig, amount runar.Bigint, feeBps runar.Bigint) {
	c.requireOwner(sig)
	runar.Assert(amount > 0)
	fee := c.computeFee(amount, feeBps)
	total := amount + fee
	runar.Assert(total <= c.Balance)
	c.Balance = c.Balance - total
}

func (c *FunctionPatterns) Scale(sig runar.Sig, numerator runar.Bigint, denominator runar.Bigint) {
	c.requireOwner(sig)
	c.Balance = c.scaleValue(c.Balance, numerator, denominator)
}

func (c *FunctionPatterns) Normalize(sig runar.Sig, lo runar.Bigint, hi runar.Bigint, step runar.Bigint) {
	c.requireOwner(sig)
	clamped := c.clampValue(c.Balance, lo, hi)
	c.Balance = c.roundDown(clamped, step)
}

func (c *FunctionPatterns) requireOwner(sig runar.Sig) {
	runar.Assert(runar.CheckSig(sig, c.Owner))
}

func (c *FunctionPatterns) computeFee(amount runar.Bigint, feeBps runar.Bigint) runar.Bigint {
	return runar.PercentOf(amount, feeBps)
}

func (c *FunctionPatterns) scaleValue(value runar.Bigint, numerator runar.Bigint, denominator runar.Bigint) runar.Bigint {
	return runar.MulDiv(value, numerator, denominator)
}

func (c *FunctionPatterns) clampValue(value runar.Bigint, lo runar.Bigint, hi runar.Bigint) runar.Bigint {
	return runar.Clamp(value, lo, hi)
}

func (c *FunctionPatterns) roundDown(value runar.Bigint, step runar.Bigint) runar.Bigint {
	remainder := runar.Safemod(value, step)
	return value - remainder
}
