// N-300: a //runar:sighash directive above a public contract method (accepting control) on the Go DSL surface.
// N-018 made a free init/main a dropped package-level function, so the
// directive attaches to no spending entry point. Every tier must refuse it
// with the same diagnostic.
package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Counter struct {
	runar.StatefulSmartContract
	Count runar.Bigint
}

//runar:sighash ALL|FORKID
func (c *Counter) Increment() {
	c.Count++
}

