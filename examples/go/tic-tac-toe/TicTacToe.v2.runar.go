package contract

import runar "github.com/icellan/runar/packages/runar-go"

// TicTacToeV2 is a FixedArray rewrite of the hand-rolled v1 contract.
//
// Semantically identical to `TicTacToe.runar.go`, with the 9 board cells
// expressed as a single `[9]runar.Bigint` property. The Rúnar compiler's
// expand-fixed-arrays pass desugars this to the same 9 scalar siblings
// that v1 declares manually, so this file must compile to byte-identical
// Bitcoin Script.
//
// This is the Go-compiler acceptance test for first-class fixed arrays.
type TicTacToeV2 struct {
	runar.StatefulSmartContract
	PlayerX     runar.PubKey     `runar:"readonly"`
	BetAmount   runar.Bigint     `runar:"readonly"`
	P2pkhPrefix runar.ByteString `runar:"readonly"`
	P2pkhSuffix runar.ByteString `runar:"readonly"`
	PlayerO     runar.PubKey
	Board       [9]runar.Bigint
	Turn        runar.Bigint
	Status      runar.Bigint
}

func (c *TicTacToeV2) init() {
	c.P2pkhPrefix = "1976a914"
	c.P2pkhSuffix = "88ac"
	c.PlayerO = "000000000000000000000000000000000000000000000000000000000000000000"
	c.Board = [9]runar.Bigint{0, 0, 0, 0, 0, 0, 0, 0, 0}
	c.Turn = 0
	c.Status = 0
}

// Join allows Player O to join the game.
func (c *TicTacToeV2) Join(opponentPK runar.PubKey, sig runar.Sig) {
	runar.Assert(c.Status == 0)
	runar.Assert(runar.CheckSig(sig, opponentPK))
	c.PlayerO = opponentPK
	c.Status = 1
	c.Turn = 1
}

// Move makes a non-terminal move. Updates board and flips turn.
func (c *TicTacToeV2) Move(position runar.Bigint, player runar.PubKey, sig runar.Sig) {
	runar.Assert(c.Status == 1)
	runar.Assert(runar.CheckSig(sig, player))
	c.assertCorrectPlayer(player)
	c.placeMove(position)
	if c.Turn == 1 {
		c.Turn = 2
	} else {
		c.Turn = 1
	}
}

// MoveAndWin makes a winning move. Non-mutating terminal method.
func (c *TicTacToeV2) MoveAndWin(position runar.Bigint, player runar.PubKey, sig runar.Sig, changePKH runar.ByteString, changeAmount runar.Bigint) {
	runar.Assert(c.Status == 1)
	runar.Assert(runar.CheckSig(sig, player))
	c.assertCorrectPlayer(player)
	c.assertCellEmpty(position)
	runar.Assert(c.checkWinAfterMove(position, c.Turn))

	totalPayout := c.BetAmount * 2
	payout := runar.Cat(runar.Cat(runar.Num2Bin(totalPayout, 8), c.P2pkhPrefix), runar.Cat(runar.Hash160(player), c.P2pkhSuffix))
	if changeAmount > 0 {
		change := runar.Cat(runar.Cat(runar.Num2Bin(changeAmount, 8), c.P2pkhPrefix), runar.Cat(changePKH, c.P2pkhSuffix))
		runar.Assert(runar.Hash256(runar.Cat(payout, change)) == runar.ExtractOutputHash(c.TxPreimage))
	} else {
		runar.Assert(runar.Hash256(payout) == runar.ExtractOutputHash(c.TxPreimage))
	}
}

// MoveAndTie makes a move that fills the board (tie). Non-mutating terminal method.
func (c *TicTacToeV2) MoveAndTie(position runar.Bigint, player runar.PubKey, sig runar.Sig, changePKH runar.ByteString, changeAmount runar.Bigint) {
	runar.Assert(c.Status == 1)
	runar.Assert(runar.CheckSig(sig, player))
	c.assertCorrectPlayer(player)
	c.assertCellEmpty(position)
	runar.Assert(c.countOccupied() == 8)
	runar.Assert(!c.checkWinAfterMove(position, c.Turn))

	out1 := runar.Cat(runar.Cat(runar.Num2Bin(c.BetAmount, 8), c.P2pkhPrefix), runar.Cat(runar.Hash160(c.PlayerX), c.P2pkhSuffix))
	out2 := runar.Cat(runar.Cat(runar.Num2Bin(c.BetAmount, 8), c.P2pkhPrefix), runar.Cat(runar.Hash160(c.PlayerO), c.P2pkhSuffix))
	if changeAmount > 0 {
		change := runar.Cat(runar.Cat(runar.Num2Bin(changeAmount, 8), c.P2pkhPrefix), runar.Cat(changePKH, c.P2pkhSuffix))
		runar.Assert(runar.Hash256(runar.Cat(runar.Cat(out1, out2), change)) == runar.ExtractOutputHash(c.TxPreimage))
	} else {
		runar.Assert(runar.Hash256(runar.Cat(out1, out2)) == runar.ExtractOutputHash(c.TxPreimage))
	}
}

// CancelBeforeJoin lets Player X cancel before anyone joins.
func (c *TicTacToeV2) CancelBeforeJoin(sig runar.Sig, changePKH runar.ByteString, changeAmount runar.Bigint) {
	runar.Assert(c.Status == 0)
	runar.Assert(runar.CheckSig(sig, c.PlayerX))
	payout := runar.Cat(runar.Cat(runar.Num2Bin(c.BetAmount, 8), c.P2pkhPrefix), runar.Cat(runar.Hash160(c.PlayerX), c.P2pkhSuffix))
	if changeAmount > 0 {
		change := runar.Cat(runar.Cat(runar.Num2Bin(changeAmount, 8), c.P2pkhPrefix), runar.Cat(changePKH, c.P2pkhSuffix))
		runar.Assert(runar.Hash256(runar.Cat(payout, change)) == runar.ExtractOutputHash(c.TxPreimage))
	} else {
		runar.Assert(runar.Hash256(payout) == runar.ExtractOutputHash(c.TxPreimage))
	}
}

// Cancel lets both players agree to cancel.
func (c *TicTacToeV2) Cancel(sigX runar.Sig, sigO runar.Sig, changePKH runar.ByteString, changeAmount runar.Bigint) {
	out1 := runar.Cat(runar.Cat(runar.Num2Bin(c.BetAmount, 8), c.P2pkhPrefix), runar.Cat(runar.Hash160(c.PlayerX), c.P2pkhSuffix))
	out2 := runar.Cat(runar.Cat(runar.Num2Bin(c.BetAmount, 8), c.P2pkhPrefix), runar.Cat(runar.Hash160(c.PlayerO), c.P2pkhSuffix))
	if changeAmount > 0 {
		change := runar.Cat(runar.Cat(runar.Num2Bin(changeAmount, 8), c.P2pkhPrefix), runar.Cat(changePKH, c.P2pkhSuffix))
		runar.Assert(runar.Hash256(runar.Cat(runar.Cat(out1, out2), change)) == runar.ExtractOutputHash(c.TxPreimage))
	} else {
		runar.Assert(runar.Hash256(runar.Cat(out1, out2)) == runar.ExtractOutputHash(c.TxPreimage))
	}
	runar.Assert(runar.CheckSig(sigX, c.PlayerX))
	runar.Assert(runar.CheckSig(sigO, c.PlayerO))
}

// --- Private helpers ---

func (c *TicTacToeV2) assertCorrectPlayer(player runar.PubKey) {
	if c.Turn == 1 {
		runar.Assert(player == c.PlayerX)
	} else {
		runar.Assert(player == c.PlayerO)
	}
}

func (c *TicTacToeV2) assertCellEmpty(position runar.Bigint) {
	if position == 0 {
		runar.Assert(c.Board[0] == 0)
	} else if position == 1 {
		runar.Assert(c.Board[1] == 0)
	} else if position == 2 {
		runar.Assert(c.Board[2] == 0)
	} else if position == 3 {
		runar.Assert(c.Board[3] == 0)
	} else if position == 4 {
		runar.Assert(c.Board[4] == 0)
	} else if position == 5 {
		runar.Assert(c.Board[5] == 0)
	} else if position == 6 {
		runar.Assert(c.Board[6] == 0)
	} else if position == 7 {
		runar.Assert(c.Board[7] == 0)
	} else if position == 8 {
		runar.Assert(c.Board[8] == 0)
	} else {
		runar.Assert(false)
	}
}

func (c *TicTacToeV2) placeMove(position runar.Bigint) {
	c.assertCellEmpty(position)
	c.Board[position] = c.Turn
}

func (c *TicTacToeV2) getCellOrOverride(cellIndex runar.Bigint, overridePos runar.Bigint, overrideVal runar.Bigint) runar.Bigint {
	if cellIndex == overridePos {
		return overrideVal
	}
	if cellIndex == 0 {
		return c.Board[0]
	} else if cellIndex == 1 {
		return c.Board[1]
	} else if cellIndex == 2 {
		return c.Board[2]
	} else if cellIndex == 3 {
		return c.Board[3]
	} else if cellIndex == 4 {
		return c.Board[4]
	} else if cellIndex == 5 {
		return c.Board[5]
	} else if cellIndex == 6 {
		return c.Board[6]
	} else if cellIndex == 7 {
		return c.Board[7]
	} else {
		return c.Board[8]
	}
}

func (c *TicTacToeV2) checkWinAfterMove(position runar.Bigint, player runar.Bigint) runar.Bool {
	v0 := c.getCellOrOverride(0, position, player)
	v1 := c.getCellOrOverride(1, position, player)
	v2 := c.getCellOrOverride(2, position, player)
	v3 := c.getCellOrOverride(3, position, player)
	v4 := c.getCellOrOverride(4, position, player)
	v5 := c.getCellOrOverride(5, position, player)
	v6 := c.getCellOrOverride(6, position, player)
	v7 := c.getCellOrOverride(7, position, player)
	v8 := c.getCellOrOverride(8, position, player)

	if v0 == player && v1 == player && v2 == player {
		return true
	}
	if v3 == player && v4 == player && v5 == player {
		return true
	}
	if v6 == player && v7 == player && v8 == player {
		return true
	}
	if v0 == player && v3 == player && v6 == player {
		return true
	}
	if v1 == player && v4 == player && v7 == player {
		return true
	}
	if v2 == player && v5 == player && v8 == player {
		return true
	}
	if v0 == player && v4 == player && v8 == player {
		return true
	}
	if v2 == player && v4 == player && v6 == player {
		return true
	}
	return false
}

func (c *TicTacToeV2) countOccupied() runar.Bigint {
	count := runar.Bigint(0)
	if c.Board[0] != 0 {
		count = count + 1
	}
	if c.Board[1] != 0 {
		count = count + 1
	}
	if c.Board[2] != 0 {
		count = count + 1
	}
	if c.Board[3] != 0 {
		count = count + 1
	}
	if c.Board[4] != 0 {
		count = count + 1
	}
	if c.Board[5] != 0 {
		count = count + 1
	}
	if c.Board[6] != 0 {
		count = count + 1
	}
	if c.Board[7] != 0 {
		count = count + 1
	}
	if c.Board[8] != 0 {
		count = count + 1
	}
	return count
}
