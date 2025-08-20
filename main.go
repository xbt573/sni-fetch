package main

import (
	"fmt"

	"github.com/xbt573/sni-fetch/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Printf("failed to run cmd: %v\n", err)
	}
}
