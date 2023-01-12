package abi

import (
	"testing"

	"github.com/indexsupply/x/tc"
)

func TestGen(t *testing.T) {
	var (
		name   = "erc721"
		events = []Event{
			Event{
				Name:      "Transfer",
				Type:      "event",
				Anonymous: false,
				Inputs: []Input{
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
			},
		}
	)
	code, err := gen(name, events)
	tc.NoErr(t, err)
	t.Error(string(code))
}
