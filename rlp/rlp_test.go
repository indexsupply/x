package rlp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func FuzzEncode(f *testing.F) {
	var (
		numItems uint64 = 10
		payload         = []byte("hello")
	)
	f.Add(numItems, payload)
	f.Fuzz(func(t *testing.T, n uint64, d []byte) {
		item := &Item{L: []*Item{}}
		for i := 0; i < int(n); i++ {
			item.L = append(item.L, &Item{D: d})
		}
		b, err := Encode(item)
		if err != nil {
			t.Fatal(err)
		}
		got := Decode(b)
		if !reflect.DeepEqual(item, got) {
			t.Errorf("want:\n%v\ngot:\n%v\n", item, got)
		}
	})
}

func BenchmarkEncode(b *testing.B) {
	payload := []byte("hello world")
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		_, err := Encode(&Item{D: payload})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func intTo2b(i uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return b
}

func TestDecode(t *testing.T) {
	cases := []struct {
		desc string
		item *Item
	}{
		{
			"short string",
			&Item{D: []byte("a")},
		},
		{
			"long string",
			&Item{D: []byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit")},
		},
		{
			"empty list",
			&Item{L: []*Item{}},
		},
		{
			"list of short strings",
			&Item{
				L: []*Item{
					&Item{D: []byte("a")},
					&Item{D: []byte("b")},
				},
			},
		},
		{
			"list of long strings",
			&Item{
				L: []*Item{
					&Item{D: []byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit")},
					&Item{D: []byte("Porem ipsum dolor sit amet, consectetur adipisicing elit")},
				},
			},
		},
		{
			"the set theoretical representation of three",
			&Item{
				L: []*Item{
					&Item{L: []*Item{}},
					&Item{L: []*Item{
						&Item{L: []*Item{}},
					}},
					&Item{L: []*Item{
						&Item{L: []*Item{}},
						&Item{L: []*Item{
							&Item{L: []*Item{}},
						}},
					}},
				},
			},
		},
	}
	for _, tc := range cases {
		b, err := Encode(tc.item)
		if err != nil {
			t.Fatal(err)
		}
		got := Decode(b)
		if !reflect.DeepEqual(tc.item, got) {
			t.Errorf("%s\nwant:\n%# v\ngot:\n%# v\n", tc.desc, tc.item, got)
		}
	}
}

func TestEncode(t *testing.T) {
	cases := []struct {
		desc string
		item *Item
		want []byte
		err  error
	}{
		{
			"missing item",
			nil,
			[]byte{},
			ErrTooFewArgs,
		},
		{
			"setting L & D",
			&Item{D: []byte{}, L: []*Item{}},
			[]byte{},
			ErrTooManyArgs,
		},
		{
			"zero byte",
			&Item{D: []byte{byte(0)}},
			[]byte{0x00},
			nil,
		},
		{
			"int 0",
			&Item{D: []byte{}},
			[]byte{0x80},
			nil,
		},
		{
			"int 1024",
			&Item{D: intTo2b(1024)},
			[]byte{0x82, 0x04, 0x00},
			nil,
		},
		{
			"empty string",
			&Item{D: []byte("")},
			[]byte{0x80},
			nil,
		},
		{
			"non-empty string",
			&Item{D: []byte("Lorem ipsum dolor sit amet, consectetur adipisicing elit")},
			[]byte{
				0xB8,
				0x38,
				0x4C,
				0x6F,
				0x72,
				0x65,
				0x6D,
				0x20,
				0x69,
				0x70,
				0x73,
				0x75,
				0x6D,
				0x20,
				0x64,
				0x6F,
				0x6C,
				0x6F,
				0x72,
				0x20,
				0x73,
				0x69,
				0x74,
				0x20,
				0x61,
				0x6D,
				0x65,
				0x74,
				0x2C,
				0x20,
				0x63,
				0x6F,
				0x6E,
				0x73,
				0x65,
				0x63,
				0x74,
				0x65,
				0x74,
				0x75,
				0x72,
				0x20,
				0x61,
				0x64,
				0x69,
				0x70,
				0x69,
				0x73,
				0x69,
				0x63,
				0x69,
				0x6E,
				0x67,
				0x20,
				0x65,
				0x6C,
				0x69,
				0x74,
			},
			nil,
		},
		{
			"empty list",
			&Item{L: []*Item{}},
			[]byte{0xc0},
			nil,
		},
		{
			"list of strings",
			&Item{
				L: []*Item{
					&Item{D: []byte("cat")},
					&Item{D: []byte("dog")},
				},
			},
			[]byte{
				0xc8, // 200
				0x83, // 131
				0x63, // c
				0x61, // a
				0x74, // t
				0x83, // 131
				0x64, // d
				0x6f, // o
				0x67, // g
			},
			nil,
		},
		{
			"the set theoretical representation of three",
			&Item{
				L: []*Item{
					&Item{L: []*Item{}},
					&Item{L: []*Item{
						&Item{L: []*Item{}},
					}},
					&Item{L: []*Item{
						&Item{L: []*Item{}},
						&Item{L: []*Item{
							&Item{L: []*Item{}},
						}},
					}},
				},
			},
			[]byte{
				0xc7,
				0xc0,
				0xc1,
				0xc0,
				0xc3,
				0xc0,
				0xc1,
				0xc0,
			},
			nil,
		},
	}
	for _, tc := range cases {
		if tc.desc != "missing item" {
			continue
		}
		got, err := Encode(tc.item)
		if err != nil {
			if !errors.Is(err, tc.err) {
				t.Fatalf("%s: want: %v got: %v", tc.desc, tc.err, err)
			}
		}
		if !bytes.Equal(tc.want, got) {
			t.Errorf("%s\nwant:\n%v\ngot:\n%v\n", tc.desc, tc.want, got)
		}
	}
}
