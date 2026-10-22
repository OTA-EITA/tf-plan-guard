package finding

import "testing"

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"high": High, "Medium": Medium, "LOW": Low} {
		if got, ok := ParseSeverity(in); !ok || got != want {
			t.Errorf("ParseSeverity(%q) = %q %v", in, got, ok)
		}
	}
	if _, ok := ParseSeverity("critical"); ok {
		t.Error("unknown severities must be rejected")
	}
}

func TestSort(t *testing.T) {
	fs := []Finding{{Severity: Low, Address: "a"}, {Severity: High, Address: "z"}, {Severity: High, Address: "b"}, {Severity: Medium, Address: "c"}}
	Sort(fs)
	want := []string{"b", "z", "c", "a"}
	for i, f := range fs {
		if f.Address != want[i] {
			t.Fatalf("order %v", fs)
		}
	}
}
