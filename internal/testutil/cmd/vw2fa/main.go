// Command vw2fa enables authenticator 2FA for a test account and prints the secret.
//
//	go run ./internal/testutil/cmd/vw2fa <server> <email> <password>
package main

import (
	"fmt"
	"os"

	"github.com/oneryx/bw/internal/testutil"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: vw2fa <server> <email> <password>")
		os.Exit(2)
	}
	s, err := testutil.Login(os.Args[1], os.Args[2], os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "login:", err)
		os.Exit(1)
	}
	key, err := s.EnableTOTP(os.Args[2], os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "enable totp:", err)
		os.Exit(1)
	}
	fmt.Println(key)
}
