package contract

import runar "github.com/icellan/runar/packages/runar-go"

// TicTacToe is an on-chain Tic-Tac-Toe contract.
//
// Two players compete on a 3x3 board. Each move is an on-chain transaction.
// The contract holds both players' bets and enforces correct game rules
// entirely in Bitcoin Script.
//
// Board encoding:
// Since Rúnar has no arrays, the 3x3 board uses 9 individual bigint fields
// (C0-C8). Values: 0=empty, 1=X, 2=O.
//
// Lifecycle:
//  1. Player X deploys the contract with their bet amount.
//  2. Player O calls Join to enter the game, adding their bet.
//  3. Players alternate calling Move (non-terminal) or
//     MoveAndWin / MoveAndTie (terminal).
//  4. Either player can propose Cancel (requires both signatures).
//
// Method types:
//   - State-mutating: Join, Move — produce a continuation UTXO.
//   - Non-mutating terminal: MoveAndWin, MoveAndTie, Cancel — spend
//     the UTXO and enforce payout outputs via ExtractOutputHash.
type TicTacToe struct {
	runar.StatefulSmartContract
	PlayerX     runar.PubKey      `runar:"readonly"`
	BetAmount   runar.Bigint      `runar:"readonly"`
	P2pkhPrefix runar.ByteString  `runar:"readonly"`
	P2pkhSuffix runar.ByteString  `runar:"readonly"`
	PlayerO     runar.PubKey
	C0          runar.Bigint
	C1          runar.Bigint
	C2          runar.Bigint
	C3          runar.Bigint
	C4          runar.Bigint
	C5          runar.Bigint
	C6          runar.Bigint
	C7          runar.Bigint
	C8          runar.Bigint
	Turn        runar.Bigint
	Status      runar.Bigint
}

func (c *TicTacToe) init() {
	c.P2pkhPrefix = "1976a914"
	c.P2pkhSuffix = "88ac"
	c.PlayerO = "000000000000000000000000000000000000000000000000000000000000000000"
	c.C0 = 0
	c.C1 = 0
	c.C2 = 0
	c.C3 = 0
	c.C4 = 0
	c.C5 = 0
	c.C6 = 0
	c.C7 = 0
	c.C8 = 0
	c.Turn = 0
	c.Status = 0
}

// Join allows Player O to join the game.
// State-mutating: produces continuation UTXO with doubled bet.
func (c *TicTacToe) Join(opponentPK runar.PubKey, sig runar.Sig) {
	runar.Assert(c.Status == 0)
	runar.Assert(runar.CheckSig(sig, opponentPK))
	c.PlayerO = opponentPK
	c.Status = 1
	c.Turn = 1
}

// Move makes a non-terminal move. Updates board and flips turn.
// State-mutating: produces continuation UTXO.
// Caller provides their pubkey; contract verifies it matches the expected turn.
func (c *TicTacToe) Move(position runar.Bigint, player runar.PubKey, sig runar.Sig) {
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
// Enforces winner-gets-all payout via ExtractOutputHash.
// Supports optional change output for fee funding.
func (c *TicTacToe) MoveAndWin(position runar.Bigint, player runar.PubKey, sig runar.Sig, changePKH runar.ByteString, changeAmount runar.Bigint) {
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
// Enforces equal split payout via ExtractOutputHash.
// Supports optional change output for fee funding.
func (c *TicTacToe) MoveAndTie(position runar.Bigint, player runar.PubKey, sig runar.Sig, changePKH runar.ByteString, changeAmount runar.Bigint) {
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

// CancelBeforeJoin lets Player X cancel before anyone joins. Non-mutating terminal method.
// Refunds the full bet to Player X.
// Supports optional change output for fee funding.
func (c *TicTacToe) CancelBeforeJoin(sig runar.Sig, changePKH runar.ByteString, changeAmount runar.Bigint) {
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

// Cancel lets both players agree to cancel. Non-mutating terminal method.
// Enforces equal refund via ExtractOutputHash.
// Supports optional change output for fee funding.
func (c *TicTacToe) Cancel(sigX runar.Sig, sigO runar.Sig, changePKH runar.ByteString, changeAmount runar.Bigint) {
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

// assertCorrectPlayer asserts the provided player pubkey matches whoever's turn it is.
func (c *TicTacToe) assertCorrectPlayer(player runar.PubKey) {
	if c.Turn == 1 {
		runar.Assert(player == c.PlayerX)
	} else {
		runar.Assert(player == c.PlayerO)
	}
}

func (c *TicTacToe) assertCellEmpty(position runar.Bigint) {
	if position == 0 {
		runar.Assert(c.C0 == 0)
	} else if position == 1 {
		runar.Assert(c.C1 == 0)
	} else if position == 2 {
		runar.Assert(c.C2 == 0)
	} else if position == 3 {
		runar.Assert(c.C3 == 0)
	} else if position == 4 {
		runar.Assert(c.C4 == 0)
	} else if position == 5 {
		runar.Assert(c.C5 == 0)
	} else if position == 6 {
		runar.Assert(c.C6 == 0)
	} else if position == 7 {
		runar.Assert(c.C7 == 0)
	} else if position == 8 {
		runar.Assert(c.C8 == 0)
	} else {
		runar.Assert(false)
	}
}

func (c *TicTacToe) placeMove(position runar.Bigint) {
	c.assertCellEmpty(position)
	if position == 0 {
		c.C0 = c.Turn
	} else if position == 1 {
		c.C1 = c.Turn
	} else if position == 2 {
		c.C2 = c.Turn
	} else if position == 3 {
		c.C3 = c.Turn
	} else if position == 4 {
		c.C4 = c.Turn
	} else if position == 5 {
		c.C5 = c.Turn
	} else if position == 6 {
		c.C6 = c.Turn
	} else if position == 7 {
		c.C7 = c.Turn
	} else if position == 8 {
		c.C8 = c.Turn
	} else {
		runar.Assert(false)
	}
}

func (c *TicTacToe) getCellOrOverride(cellIndex runar.Bigint, overridePos runar.Bigint, overrideVal runar.Bigint) runar.Bigint {
	if cellIndex == overridePos {
		return overrideVal
	}
	if cellIndex == 0 {
		return c.C0
	} else if cellIndex == 1 {
		return c.C1
	} else if cellIndex == 2 {
		return c.C2
	} else if cellIndex == 3 {
		return c.C3
	} else if cellIndex == 4 {
		return c.C4
	} else if cellIndex == 5 {
		return c.C5
	} else if cellIndex == 6 {
		return c.C6
	} else if cellIndex == 7 {
		return c.C7
	} else {
		return c.C8
	}
}

func (c *TicTacToe) checkWinAfterMove(position runar.Bigint, player runar.Bigint) runar.Bool {
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

func (c *TicTacToe) countOccupied() runar.Bigint {
	count := runar.Bigint(0)
	if c.C0 != 0 {
		count = count + 1
	}
	if c.C1 != 0 {
		count = count + 1
	}
	if c.C2 != 0 {
		count = count + 1
	}
	if c.C3 != 0 {
		count = count + 1
	}
	if c.C4 != 0 {
		count = count + 1
	}
	if c.C5 != 0 {
		count = count + 1
	}
	if c.C6 != 0 {
		count = count + 1
	}
	if c.C7 != 0 {
		count = count + 1
	}
	if c.C8 != 0 {
		count = count + 1
	}
	return count
}
