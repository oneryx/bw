package cli

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestJoinOptionalValues(t *testing.T) {
	cases := []struct{ in, want []string }{
		{[]string{"export", "--password", "pw", "--format", "json"}, []string{"export", "--password=pw", "--format", "json"}},
		{[]string{"export", "--password", "--format", "json"}, []string{"export", "--password", "--format", "json"}},
		{[]string{"--session", "export", "list", "items"}, []string{"--session", "export", "list", "items"}},
		{[]string{"get", "item", "--password", "x"}, []string{"get", "item", "--password", "x"}},
	}
	for _, tc := range cases {
		if got := joinOptionalValues(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestSaveFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	sep := string(filepath.Separator)
	cases := []struct{ out, want string }{
		{"", "default.txt"},
		{"name.txt", "name.txt"},
		{"sub" + sep, filepath.Join("sub", "default.txt")},
		{filepath.Join("deep", "x", "f.txt"), filepath.Join("deep", "x", "f.txt")},
	}
	for _, tc := range cases {
		p, err := saveFile([]byte("data"), tc.out, "default.txt")
		if err != nil {
			t.Fatalf("%q: %v", tc.out, err)
		}
		if want := filepath.Join(dir, tc.want); p != want {
			t.Errorf("%q: saved to %s want %s", tc.out, p, want)
		}
		if b, err := os.ReadFile(p); err != nil || string(b) != "data" {
			t.Errorf("%q: content %q %v", tc.out, b, err)
		}
	}
}
