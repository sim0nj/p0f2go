package p0f

import "testing"

func TestDataNotEmpty(t *testing.T) {
	if len(Data.Entries) == 0 {
		t.Fatalf("empty data")
	}
	found := false
	for _, e := range Data.Entries {
		if e.Section == "http:response" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing http:response section")
	}
}
