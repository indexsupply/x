// ABI encoding/decoding with log parsing
//
// Implementation based on the [ABI Spec].
//
// [ABI Spec]: https://docs.soliditylang.org/en/latest/abi-spec.html
package abi

import (
	"math/big"
	"strings"

	"github.com/indexsupply/x/abi/abit"
	"github.com/indexsupply/x/bint"
	"github.com/indexsupply/x/isxhash"
)

type Log struct {
	Address [20]byte
	Topics  [4][32]byte
	Data    []byte
}

// Matches event data in a log. Sets decoded data on e.
// Use [Input]'s Item field to read decoded data.
//
// A false return value indicates the first log topic doesn't match
// the event's [Event.SignatureHash].
func Match(l Log, e Event) (Item, bool) {
	if e.SignatureHash() != l.Topics[0] {
		return Item{}, false
	}
	var (
		items     = make([]Item, len(e.Inputs))
		unindexed []abit.Type
	)
	for i, inp := range e.Inputs {
		if !inp.Indexed {
			unindexed = append(unindexed, inp.ABIType())
			continue
		}
		items[i] = Bytes(l.Topics[i+1][:])
	}
	item := Decode(l.Data, abit.Tuple(unindexed...))
	for i, j := 0, 0; i < len(e.Inputs); i++ {
		if e.Inputs[i].Indexed {
			continue
		}
		items[i] = item.At(j)
		j++
	}
	return Tuple(items...), true
}

// Optionally contains a decoded Item. See: [Match].
type Input struct {
	Item *Item

	Indexed    bool
	Name       string
	Type       string
	Gtype      string
	Components []Input
}

// Returns a fully formed abit.Type for the input
// by recursively iterating through the components
// and '[]' list.
func (inp *Input) ABIType() abit.Type {
	if !strings.HasPrefix(inp.Type, "tuple") {
		return abit.Resolve(inp.Type)
	}
	var types []abit.Type
	for _, c := range inp.Components {
		types = append(types, c.ABIType())
	}
	return abit.Resolve(inp.Type, types...)
}

type Event struct {
	sig     string
	sigHash [32]byte

	Name      string
	Type      string //event
	Anonymous bool
	Inputs    []Input
}

// Computes signature (eg name(type1,type2)). Caches result on e
func (e *Event) Signature() string {
	if e.sig != "" {
		return e.sig
	}
	var s strings.Builder
	s.WriteString(e.Name)
	s.WriteString("(")
	for i := range e.Inputs {
		s.WriteString(e.Inputs[i].ABIType().Signature())
		if i+1 < len(e.Inputs) {
			s.WriteString(",")
		}
	}
	s.WriteString(")")
	e.sig = s.String()
	return e.sig
}

// Computes keccak hash over [Event.Signature]. Caches result on e
func (e *Event) SignatureHash() [32]byte {
	if e.sigHash != [32]byte{} {
		return e.sigHash
	}
	e.sigHash = isxhash.Keccak32([]byte(e.Signature()))
	return e.sigHash
}

type Item struct {
	abit.Type

	// must be d XOR l
	d []byte
	l []Item
}

func Bytes(d []byte) Item {
	return Item{Type: abit.Bytes, d: d}
}

func (it Item) Bytes() []byte {
	return it.d
}

func (it Item) BytesSlice() [][]byte {
	var res [][]byte
	for i := range it.l {
		res = append(res, it.l[i].Bytes())
	}
	return res
}

func (it Item) Address() [20]byte {
	if len(it.d) < 32 {
		return [20]byte{}
	}
	return *(*[20]byte)(it.d[12:])
}

func (it Item) AddressSlice() [][20]byte {
	var res [][20]byte
	for i := range it.l {
		res = append(res, it.l[i].Address())
	}
	return res
}

func String(s string) Item {
	return Item{Type: abit.String, d: []byte(s)}
}

func (it Item) String() string {
	return string(it.d)
}

func (it Item) StringSlice() []string {
	var res []string
	for i := range it.l {
		res = append(res, it.l[i].String())
	}
	return res
}

func Bool(b bool) Item {
	var d [32]byte
	if b {
		d[31] = 1
	}
	return Item{Type: abit.Bool, d: d[:]}
}

func (it Item) Bool() bool {
	if len(it.d) < 32 {
		return false
	}
	return it.d[31] == 1
}

func (it Item) BoolSlice() []bool {
	var res []bool
	for i := range it.l {
		res = append(res, it.l[i].Bool())
	}
	return res
}

func BigInt(i *big.Int) Item {
	var b [32]byte
	i.FillBytes(b[:])
	return Item{
		Type: abit.Uint256,
		d:    b[:],
	}
}

func (it Item) BigInt() *big.Int {
	x := &big.Int{}
	x.SetBytes(it.d)
	return x
}

func (it Item) BigIntSlice() []*big.Int {
	var res []*big.Int
	for i := range it.l {
		res = append(res, it.l[i].BigInt())
	}
	return res
}

func Uint64(i uint64) Item {
	var b [32]byte
	bint.Encode(b[:], i)
	return Item{Type: abit.Uint64, d: b[:]}
}

func (it Item) Uint64() uint64 {
	return bint.Decode(it.d)
}

func (it Item) Uint64Slice() []uint64 {
	var res []uint64
	for i := range it.l {
		res = append(res, it.l[i].Uint64())
	}
	return res
}

func Uint8(i uint8) Item {
	var b [32]byte
	bint.Encode(b[:], uint64(i))
	return Item{Type: abit.Uint8, d: b[:]}
}

func (it Item) Uint8() uint8 {
	return uint8(bint.Decode(it.d))
}

func (it Item) Uint8Slice() []uint8 {
	var res []uint8
	for i := range it.l {
		res = append(res, it.l[i].Uint8())
	}
	return res
}

func List(items ...Item) Item {
	return Item{
		Type: abit.List(items[0].Type),
		l:    items,
	}
}

func (it Item) At(i int) Item {
	if len(it.l) <= i {
		return Item{}
	}
	return it.l[i]
}

// Returns length of list, tuple, or bytes depending
// on how the item was constructed.
func (it Item) Len() int {
	if len(it.l) > 0 {
		return len(it.l)
	}
	return len(it.d)
}

func Tuple(items ...Item) Item {
	var types []abit.Type
	for i := range items {
		types = append(types, items[i].Type)
	}
	return Item{
		Type: abit.Tuple(types...),
		l:    items,
	}
}

func rpad(l int, d []byte) []byte {
	n := len(d) % l
	if n == 0 {
		return d
	}
	return append(d, make([]byte, l-n)...)
}

// ABI encoding. Not packed.
func Encode(it Item) []byte {
	switch it.Kind {
	case abit.S:
		return it.d
	case abit.D:
		var c [32]byte
		bint.Encode(c[:], uint64(len(it.d)))
		return append(c[:], rpad(32, it.d)...)
	case abit.L:
		var c [32]byte
		bint.Encode(c[:], uint64(len(it.l)))
		return append(c[:], Encode(Tuple(it.l...))...)
	case abit.T:
		var head, tail []byte
		for i := range it.l {
			switch it.l[i].Kind {
			case abit.S:
				head = append(head, Encode(it.l[i])...)
			default:
				var offset [32]byte
				bint.Encode(offset[:], uint64(len(it.l)*32+len(tail)))
				head = append(head, offset[:]...)
				tail = append(tail, Encode(it.l[i])...)
			}
		}
		return append(head, tail...)
	default:
		panic("abi: encode: unkown type")
	}
}

// Decodes ABI encoded bytes into an [Item] according to
// the 'schema' defined by t. For example:
//
//	Decode(b, abit.Tuple(abit.String, abit.Uint256))
func Decode(input []byte, t abit.Type) Item {
	switch t.Kind {
	case abit.S:
		return Item{Type: t, d: input[:32]}
	case abit.D:
		count := bint.Decode(input[:32])
		return Item{Type: t, d: input[32 : 32+count]}
	case abit.L:
		count := bint.Decode(input[:32])
		items := make([]Item, count)
		for i := uint64(0); i < count; i++ {
			n := 32 + (32 * i) //skip count (head)
			switch t.Elem.Kind {
			case abit.S:
				items[i] = Decode(input[n:], *t.Elem)
			default:
				offset := 32 + bint.Decode(input[n:n+32])
				items[i] = Decode(input[offset:], *t.Elem)
			}
		}
		return List(items...)
	case abit.T:
		items := make([]Item, len(t.Fields))
		for i, f := range t.Fields {
			n := 32 * i
			switch f.Kind {
			case abit.S:
				items[i] = Decode(input[n:n+32], *f)
			default:
				offset := bint.Decode(input[n : n+32])
				items[i] = Decode(input[offset:], *f)
			}
		}
		return Tuple(items...)
	default:
		panic("abi: encode: unkown type")
	}
}
