// This package implements a basic encoder/decoder for
// Ethereum's Recursive-Length Prefix (RLP) Serialization.
// For a detailed description of RLP, see Ethereum's  page:
// https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
package rlp

import "encoding/binary"

const (
	str1L, str1H     byte = 000, 127
	str55L, str55H   byte = 128, 183
	strNL, strNH     byte = 184, 191
	list55L, list55H byte = 192, 247
	listNL, listNH   byte = 248, 255
)

// Instead of using standard data types and reflection
// this package chooses to encode Items.
// Set D or L but not both.
// L is a list of *Item so that arbitrarily nested lists
// can be encoded.
// D is the data payload for the item.
type Item struct {
	D []byte
	L []*Item
}

func Encode(input *Item) []byte {
	if input.D != nil {
		switch n := len(input.D); {
		case n == 1 && input.D[0] <= str1H:
			return input.D
		case n <= 55:
			return append(
				[]byte{str55L + byte(n)},
				input.D...,
			)
		default:
			return append(
				encodeLength(str55H, len(input.D)),
				input.D...,
			)
		}
	}

	var out []byte
	for i := range input.L {
		out = append(out, Encode(input.L[i])...)
	}
	if len(out) <= 55 {
		return append(
			[]byte{list55L + byte(len(out))},
			out...,
		)
	}
	return append(
		encodeLength(list55H, len(out)),
		out...,
	)
}

func encodeLength(t byte, l int) []byte {
	// header must be <= 8 bytes
	buf := make([]byte, 8)
	// bytes needed to encode length
	n := binary.PutUvarint(buf, uint64(l))
	return append(
		[]byte{byte(uint8(t) + uint8(n))},
		buf[:n]...,
	)
}

func decodeLength(t byte, input []byte) int {
	n := input[0] - t
	length, _ := binary.Uvarint(input[1 : n+1])
	return int(n) + int(length)
}

func Decode(input []byte) *Item {
	switch {
	case input[0] <= str1H:
		return &Item{D: []byte{input[0]}}
	case input[0] <= str55H:
		i := 1
		n := input[0] - str1H
		return &Item{D: input[i:n]}
	case input[0] <= strNH:
		i := int(1 + (input[0] - str55H)) //head length
		n := 1                            //header byte
		n += decodeLength(str55H, input)
		return &Item{D: input[i:n]}
	default:
		// The first byte indicates a list
		// and if the first byte is >= 248 (listNL)
		// then the list has a length > 55 and
		// therefore the next (input[0]-247 (list55H))
		// bytes will describe the length of the list.
		// We advance the cursor i past the length description.
		i := 1
		if input[0] >= listNL {
			i += int(input[0] - list55H)
		}

		item := &Item{L: []*Item{}}
		for i < len(input) {
			var n int
			switch {
			case input[i] <= str1H:
				// 1 byte string
				n = 1
			case input[i] <= str55H:
				// <= 55 byte string
				n += 1 //header byte
				n += int(input[i] - str55L)
			case input[i] <= strNH:
				// > 55 byte string
				n += 1 //header byte
				n += decodeLength(str55H, input[i:])
			case input[i] <= list55H:
				n += 1 // header byte
				n += int(input[i] - list55L)
			default:
				n += 1 //header byte
				n += decodeLength(list55H, input[i:])
			}

			item.L = append(item.L, Decode(input[i:i+n]))
			i += n
		}
		return item
	}
}
