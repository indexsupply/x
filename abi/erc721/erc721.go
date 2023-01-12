package erc721

import (
	"math/big"

	"github.com/indexsupply/x/abi"
)

var TransferEvent = Event{
	Name:      "Transfer",
	Type:      "event",
	Anonymous: false,
	Inputs: []abi.Input{
		{
			Indexed: true,
			Name:    "To",
			Type:    "address",
		},
		{
			Indexed: true,
			Name:    "From",
			Type:    "address",
		},
		{
			Indexed: true,
			Name:    "TokenId",
			Type:    "uint256",
		},
	},
}

type Transfer struct {
	From    [20]byte
	To      [20]byte
	TokenID *big.Int
}

func MatchTransfer(l *Log) (*Transfer, bool) {
	if TransferEvent.SignatureHash() != l.Topics[0] {
		return nil, false
	}

	transfer := &Transfer{
		From:    Bytes(l.Topics[1]).Address(),
		To:      Bytes(l.Topics[2]).Address(),
		TokenID: Bytes(l.Topics[3]).BigInt(),
	}

	return transfer
}
