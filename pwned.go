package bw

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// PasswordExposures returns how often a password appears in known data
// breaches, using the Have I Been Pwned range API (only the first five
// characters of the password's SHA-1 hash are sent).
func (c *Client) PasswordExposures(ctx context.Context, password string) (int, error) {
	sum := sha1.Sum([]byte(password))
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pwnedpasswords.com/range/"+h[:5], nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		suffix, count, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && suffix == h[5:] {
			var n int
			fmt.Sscan(count, &n)
			return n, nil
		}
	}
	return 0, nil
}
