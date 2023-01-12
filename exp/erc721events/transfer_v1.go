package erc721events

import (
	"github.com/indexsupply/x/abi"
)

type Transfer struct {
	To      abi.Item
	From    abi.Item
	TokenId abi.Item
}

var TransferEvent = abi.Event{
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

func MatchTransfer(l abi.Log) *Transfer {
	items, matched := abi.Match(l, &TransferEvent)
	if !matched {
		return nil
	}
	return &Transfer{
		To:      items["To"],
		From:    items["From"],
		TokenId: items["TokenId"],
	}
}
