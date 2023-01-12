package main

import (
	"fmt"

	"github.com/indexsupply/x/abi/nested"
)

func main() {
	b, err := nested.Generate()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}
