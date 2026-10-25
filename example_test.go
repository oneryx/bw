package bw_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/oneryx/bw"
)

func Example() {
	ctx := context.Background()
	c, err := bw.New(bw.Options{Store: bw.FileStore("/path/to/data.json")})
	if err != nil {
		panic(err)
	}
	if !c.LoggedIn() {
		_ = c.SetServerConfig(bw.ServerConfig{Base: "https://vault.example.com"})
		err = c.Login(ctx, bw.LoginOptions{Email: "you@example.com", Password: "master password"})
		var tf *bw.TwoFactorRequiredError
		if errors.As(err, &tf) {
			// tf.Providers lists the available methods; tf.SendEmail sends an email code.
			err = tf.Submit(ctx, bw.TwoFactorAuthenticator, "123456")
		}
	} else {
		err = c.Unlock("master password") // the user key is kept in memory only
	}
	if err != nil {
		panic(err)
	}
	items, err := c.Items(bw.ItemFilter{Search: "github"})
	if err != nil {
		panic(err)
	}
	for _, it := range items {
		fmt.Println(it.ID, it.Name)
	}
	data, fileName, err := c.Export(ctx, bw.ExportOptions{Format: "json"})
	fmt.Println(len(data), fileName, err)
}
