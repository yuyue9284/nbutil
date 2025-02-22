package main

import (
	"fmt"

	"github.com/yuyue9284/nbutil/pkg"
)

func main() {
	filename := "test.json.nb"
	nb, err := pkg.ParseNBFile(filename)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	fmt.Printf("Parsed NBFile: %+v\n", nb)
}
