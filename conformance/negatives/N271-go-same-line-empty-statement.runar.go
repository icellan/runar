// N-154: a same-line `;` that SEPARATES two statements is valid Go and every
// tier accepts it (`runar.Assert(x == c.T);` compiles like the newline form).
// A second `;` right after it is an EMPTY statement, which stays refused
// (N-153) in every tier; the TS reference says:
//   Unexpected token in expression: ';'
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type N271 struct {
	runar.SmartContract
	T runar.Bigint `runar:"readonly"`
}

func (c *N271) Unlock(x runar.Bigint) {
	runar.Assert(x == c.T);;
}
