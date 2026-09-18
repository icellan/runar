package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

func TestArrayWrite_Compile(t *testing.T) {
	if err := runar.CompileCheck("ArrayWrite.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}

// Bump(i) increments exactly one slot. The teeth are the OTHER three: an
// indexed WRITE that lands in the wrong scalar sibling, or that writes all of
// them, still leaves the bumped slot correct -- so checking only Table[i] would
// pass on both defects.
func TestArrayWrite_BumpsExactlyOneSlot(t *testing.T) {
	for target := 0; target < 4; target++ {
		c := &ArrayWrite{}
		c.init()
		c.Bump(runar.Int(target))

		for i := 0; i < 4; i++ {
			want := runar.Int(0)
			if i == target {
				want = 1
			}
			if c.Table[i] != want {
				t.Fatalf("Bump(%d): Table = %v, want slot %d to be 1 and the rest 0",
					target, c.Table, target)
			}
		}
	}
}

func TestArrayWrite_BumpAccumulates(t *testing.T) {
	c := &ArrayWrite{}
	c.init()
	c.Bump(2)
	c.Bump(2)
	c.Bump(0)
	if got, want := c.Table, [4]runar.Int{1, 0, 2, 0}; got != want {
		t.Fatalf("Table = %v, want %v", got, want)
	}
}
