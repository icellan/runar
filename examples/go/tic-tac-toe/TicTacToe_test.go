package contract

import (
	"testing"

	runar "github.com/icellan/runar/packages/runar-go"
)

var (
	playerXPK  = runar.Alice.PubKey
	playerOPK  = runar.Bob.PubKey
	playerXSig = runar.SignTestMessage(runar.Alice.PrivKey)
	playerOSig = runar.SignTestMessage(runar.Bob.PrivKey)
)

func newGame() *TicTacToe {
	g := &TicTacToe{
		PlayerX:   playerXPK,
		BetAmount: 5000,
	}
	g.init()
	return g
}

func newPlayingGame() *TicTacToe {
	g := newGame()
	g.Join(playerOPK, playerOSig)
	return g
}

func TestTicTacToe_Join(t *testing.T) {
	g := newGame()
	if g.Status != 0 {
		t.Fatalf("expected status=0 before join, got %d", g.Status)
	}
	g.Join(playerOPK, playerOSig)
	if g.PlayerO != playerOPK {
		t.Errorf("expected playerO=%s, got %s", playerOPK, g.PlayerO)
	}
	if g.Status != 1 {
		t.Errorf("expected status=1 after join, got %d", g.Status)
	}
	if g.Turn != 1 {
		t.Errorf("expected turn=1 after join, got %d", g.Turn)
	}
}

func TestTicTacToe_JoinRejectsWhenPlaying(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when joining a game already in progress")
		}
	}()
	g := newPlayingGame()
	g.Join(playerOPK, playerOSig)
}

func TestTicTacToe_Move(t *testing.T) {
	g := newPlayingGame()
	// Turn=1 means player X moves
	g.Move(4, playerXPK, playerXSig)
	if g.C4 != 1 {
		t.Errorf("expected c4=1 (X), got %d", g.C4)
	}
	if g.Turn != 2 {
		t.Errorf("expected turn=2 after X moves, got %d", g.Turn)
	}
}

func TestTicTacToe_MoveAlternatesTurn(t *testing.T) {
	g := newPlayingGame()
	g.Move(0, playerXPK, playerXSig) // X plays position 0
	if g.Turn != 2 {
		t.Fatalf("expected turn=2, got %d", g.Turn)
	}
	g.Move(4, playerOPK, playerOSig) // O plays position 4
	if g.Turn != 1 {
		t.Fatalf("expected turn=1, got %d", g.Turn)
	}
	g.Move(1, playerXPK, playerXSig) // X plays position 1
	if g.Turn != 2 {
		t.Fatalf("expected turn=2, got %d", g.Turn)
	}
}

func TestTicTacToe_MoveRejectsOccupied(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when placing on occupied cell")
		}
	}()
	g := newPlayingGame()
	g.Move(4, playerXPK, playerXSig)
	// Now c4 is occupied, O tries to play there
	g.Move(4, playerOPK, playerOSig)
}

func TestTicTacToe_MoveRejectsWrongPlayer(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure when wrong player moves")
		}
	}()
	g := newPlayingGame()
	// Turn=1 means X should move, but O tries
	g.Move(4, playerOPK, playerOSig)
}

func TestTicTacToe_MoveRejectsInvalidPosition(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected assertion failure for invalid position")
		}
	}()
	g := newPlayingGame()
	g.Move(9, playerXPK, playerXSig) // position 9 doesn't exist
}

func TestTicTacToe_FullGameFlow(t *testing.T) {
	g := newPlayingGame()
	// X@0, O@3, X@1, O@4 — set up X to win with position 2 (top row)
	g.Move(0, playerXPK, playerXSig)
	if g.C0 != 1 {
		t.Fatalf("expected c0=1, got %d", g.C0)
	}
	g.Move(3, playerOPK, playerOSig)
	if g.C3 != 2 {
		t.Fatalf("expected c3=2, got %d", g.C3)
	}
	g.Move(1, playerXPK, playerXSig)
	if g.C1 != 1 {
		t.Fatalf("expected c1=1, got %d", g.C1)
	}
	g.Move(4, playerOPK, playerOSig)
	if g.C4 != 2 {
		t.Fatalf("expected c4=2, got %d", g.C4)
	}
	if g.Turn != 1 {
		t.Fatalf("expected turn=1 (X's turn), got %d", g.Turn)
	}

	// X plays position 2 to win top row (0,1,2).
	// Pre-compute the expected payout so we can set TxPreimage = Hash256(payout),
	// satisfying the ExtractOutputHash assertion in MoveAndWin.
	totalPayout := g.BetAmount * 2
	payout := runar.Cat(runar.Cat(runar.Num2Bin(totalPayout, 8), g.P2pkhPrefix), runar.Cat(runar.Hash160(playerXPK), g.P2pkhSuffix))
	g.TxPreimage = runar.Hash256(payout)
	g.MoveAndWin(2, playerXPK, playerXSig, "00", 0)
}

func TestTicTacToe_CheckWinRow(t *testing.T) {
	g := newPlayingGame()
	// Set up X winning top row: positions 0, 1, 2
	g.C0 = 1
	g.C1 = 1
	// Check win after placing at position 2 for player 1 (X)
	if !g.checkWinAfterMove(2, 1) {
		t.Fatal("expected win for X with top row")
	}
}

func TestTicTacToe_CheckWinColumn(t *testing.T) {
	g := newPlayingGame()
	// Set up X winning left column: positions 0, 3, 6
	g.C0 = 1
	g.C3 = 1
	if !g.checkWinAfterMove(6, 1) {
		t.Fatal("expected win for X with left column")
	}
}

func TestTicTacToe_CheckWinDiagonal(t *testing.T) {
	g := newPlayingGame()
	// Set up X winning main diagonal: positions 0, 4, 8
	g.C0 = 1
	g.C4 = 1
	if !g.checkWinAfterMove(8, 1) {
		t.Fatal("expected win for X with main diagonal")
	}
}

func TestTicTacToe_CheckWinAntiDiagonal(t *testing.T) {
	g := newPlayingGame()
	// Set up O winning anti-diagonal: positions 2, 4, 6
	g.C2 = 2
	g.C4 = 2
	if !g.checkWinAfterMove(6, 2) {
		t.Fatal("expected win for O with anti-diagonal")
	}
}

func TestTicTacToe_NoWin(t *testing.T) {
	g := newPlayingGame()
	// No winning condition
	g.C0 = 1
	g.C1 = 2
	if g.checkWinAfterMove(2, 1) {
		t.Fatal("expected no win")
	}
}

func TestTicTacToe_CountOccupied(t *testing.T) {
	g := newPlayingGame()
	if g.countOccupied() != 0 {
		t.Fatalf("expected 0 occupied, got %d", g.countOccupied())
	}
	g.C0 = 1
	g.C4 = 2
	g.C8 = 1
	if g.countOccupied() != 3 {
		t.Fatalf("expected 3 occupied, got %d", g.countOccupied())
	}
}

func TestTicTacToe_Compile(t *testing.T) {
	if err := runar.CompileCheck("TicTacToe.runar.go"); err != nil {
		t.Fatalf("Rúnar compile check failed: %v", err)
	}
}
