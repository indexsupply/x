package erc721events

import (
	"math/big"

	"github.com/indexsupply/x/abi"
)

type Address = [20]byte

type TransferV2 struct {
	To      [20]byte
	From    [20]byte
	TokenId *big.Int
}

func MatchTransferV2(l abi.Log) *TransferV2 {
	items, matched := abi.Match(l, &TransferEvent)
	if !matched {
		return nil
	}
	return &TransferV2{
		To:      items["To"].Address(),
		From:    items["From"].Address(),
		TokenId: items["TokenId"].BigInt(),
	}
}
