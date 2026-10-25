package export

import "testing"

func TestUnparseCSV(t *testing.T) {
	r1 := &CSVRow{Keys: []string{"a", "b", "c"}, Values: map[string]any{"a": "x,y", "b": []string{"1", "2"}, "c": "line1\nq\"uote"}}
	r2 := &CSVRow{Keys: []string{"a", "b", "c"}, Values: map[string]any{"a": nil, "b": " lead", "c": 3}}
	got := UnparseCSV([]*CSVRow{r1, r2})
	want := "a,b,c\r\n\"x,y\",\"1,2\",\"line1\nq\"\"uote\"\r\n,\" lead\",3"
	if got != want {
		t.Fatalf("got %q", got)
	}
}
