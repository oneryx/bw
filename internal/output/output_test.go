package output

import (
	"bytes"
	"testing"
)

func run(opts Options, r Response) (string, string, int) {
	var out, errb bytes.Buffer
	p := &Printer{Opts: opts, Stdout: &out, Stderr: &errb}
	code := p.Print(r)
	return out.String(), errb.String(), code
}

func TestPrinterMatchesOfficialSemantics(t *testing.T) {
	cases := []struct {
		name     string
		opts     Options
		resp     Response
		out, err string
		code     int
	}{
		{"string raw value", Options{}, String("p@ss"), "p@ss", "", 0},
		{"list json", Options{}, List([]int{1, 2}), "[1,2]", "", 0},
		{"pretty", Options{Pretty: true}, List([]string{"a"}), "[\n  \"a\"\n]", "", 0},
		{"no html escaping", Options{}, List([]string{"a&b<c>"}), `["a&b<c>"]`, "", 0},
		{"message", Options{}, Message("Title", "body", "raw"), "Title\nbody", "", 0},
		{"message raw", Options{Raw: true}, Message("Title", "body", "raw"), "raw", "", 0},
		{"message raw missing", Options{Raw: true}, Message("Title", "", ""), "", "", 0},
		{"error to stderr", Options{}, Error("Not found."), "", "Not found.", 1},
		{"error --response", Options{Response: true}, Error("Not found."), `{"success":false,"message":"Not found."}`, "", 1},
		{"cleanexit", Options{CleanExit: true}, Error("x"), "", "x", 0},
		{"quiet", Options{Quiet: true}, String("x"), "", "", 0},
		{"quiet error", Options{Quiet: true}, Error("x"), "", "", 1},
		{"response success", Options{Response: true}, String("x"), `{"success":true,"data":{"object":"string","data":"x"}}`, "", 0},
		{"message --response", Options{Response: true}, Message("T", "", ""), `{"success":true,"data":{"noColor":false,"object":"message","title":"T","message":null}}`, "", 0},
		{"template", Options{}, Template(map[string]int{"a": 1}), `{"a":1}`, "", 0},
	}
	for _, c := range cases {
		out, errs, code := run(c.opts, c.resp)
		if out != c.out || errs != c.err || code != c.code {
			t.Errorf("%s: got (%q, %q, %d) want (%q, %q, %d)", c.name, out, errs, code, c.out, c.err, c.code)
		}
	}
}
