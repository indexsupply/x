package nested

import (
	"math/big"

	"github.com/indexsupply/x/abi"
)

var e = abi.Event{
	Name: "e",
	Type: "event",
	Inputs: []abi.Input{
		{
			Name:    "s",
			Type:    "tuple",
			Indexed: false,
			Components: []abi.Input{
				{
					Name:    "a",
					Type:    "uint256",
					Gtype:   "*big.Int",
					Indexed: false,
				},
				{
					Name:    "b",
					Type:    "uint256",
					Gtype:   "*big.Int",
					Indexed: false,
				},
				{
					Name:    "c",
					Type:    "tuple",
					Gtype:   "struct",
					Indexed: false,
					Components: []abi.Input{
						{
							Name:    "x",
							Indexed: false,
							Gtype:   "*big.Int",
							Type:    "uint256",
						},
						{
							Name:    "y",
							Indexed: false,
							Gtype:   "*big.Int",
							Type:    "uint256",
						},
					},
				},
			},
		},
	},
}

type E struct {
	S struct {
		A *big.Int
		B *big.Int
		C struct {
			X *big.Int
			Y *big.Int
		}
	}
}
