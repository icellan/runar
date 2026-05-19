package ir

import "fmt"

// UnknownANFKindError is raised by ANF dispatch switches when they
// encounter a kind they don't know how to handle — typically because
// a new ANFValue variant was added without updating all dispatch
// sites per CLAUDE.md § Adding a New ANF Value Kind.
//
// Historically these dispatchers used silent default fall-throughs
// (return nil refs, return v unchanged, return false from
// hasSideEffect) so an unhandled kind would silently corrupt output
// (dropped live binding, missed last-use, dead-code-eliminated
// side-effecting binding) instead of failing loudly. Every former
// silent default now panics with this typed error so the regression
// is caught at the first dispatch site instead of leaking into
// Stack IR / hex.
type UnknownANFKindError struct {
	Kind     string
	Location string // e.g. "stack.lowerBinding"
}

func (e *UnknownANFKindError) Error() string {
	return fmt.Sprintf("unknown ANF kind %q encountered in %s — "+
		"if you added a new ANFValue variant, update all dispatch sites "+
		"(see CLAUDE.md § Adding a New ANF Value Kind)", e.Kind, e.Location)
}
