// Command vwregister creates a test account on a Vaultwarden server.
//
//	go run ./internal/testutil/cmd/vwregister http://127.0.0.1:18080 user@example.com password
package main

import (
	"fmt"
	"os"

	"github.com/yangxiang/bw/internal/testutil"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: vwregister <server-url> <email> <password>")
		os.Exit(2)
	}
	if err := testutil.Register(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("registered", os.Args[2])
}
