package main

func HandValue(cards []Card) int {
	total := 0
	aces := 0

	for _, c := range cards {
		v := CardValue(c.Rank)
		total += v
		if c.Rank == 1 {
			aces++
		}
	}

	for aces > 0 && total > 21 {
		total -= 10
		aces--
	}

	return total
}

func IsBlackjack(cards []Card) bool {
	return len(cards) == 2 && HandValue(cards) == 21
}

func IsBust(cards []Card) bool {
	return HandValue(cards) > 21
}

func DealerShouldHit(cards []Card) bool {
	return HandValue(cards) <= 16
}

func CompareHands(playerVal, dealerVal int, playerBJ, dealerBJ bool) string {
	if playerBJ && dealerBJ {
		return "push"
	}
	if playerBJ {
		return "blackjack"
	}
	if dealerBJ {
		return "lose"
	}
	if playerVal > 21 {
		return "lose"
	}
	if dealerVal > 21 {
		return "win"
	}
	if playerVal > dealerVal {
		return "win"
	}
	if playerVal < dealerVal {
		return "lose"
	}
	return "push"
}
