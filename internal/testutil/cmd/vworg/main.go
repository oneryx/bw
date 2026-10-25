// Command vworg creates an organization (and optionally invites a member) for manual testing.
//
//	go run ./internal/testutil/cmd/vworg <server> <email> <password> <org-name> [invite-email]
package main

import (
	"fmt"
	"os"

	"github.com/yangxiang/bw/internal/testutil"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: vworg <server> <email> <password> <org-name> [invite-email]")
		os.Exit(2)
	}
	s, err := testutil.Login(os.Args[1], os.Args[2], os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "login:", err)
		os.Exit(1)
	}
	org, err := s.CreateOrg(os.Args[4], "Default Collection")
	if err != nil {
		fmt.Fprintln(os.Stderr, "create org:", err)
		os.Exit(1)
	}
	fmt.Println("org", org)
	if len(os.Args) > 5 {
		m, err := s.Invite(org, os.Args[5])
		if err != nil {
			fmt.Fprintln(os.Stderr, "invite:", err)
			os.Exit(1)
		}
		fmt.Println("member", m)
	}
}
