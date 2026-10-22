package plan

import "testing"

func TestAction(t *testing.T) {
	cases := map[Action][]string{
		Replace: {"delete", "create"},
		NoOp:    {"no-op"},
		Read:    {"read"},
		Create:  {"create"},
		Update:  {"update"},
		Delete:  {"delete"},
	}
	for want, actions := range cases {
		if got := (Change{Actions: actions}).Action(); got != want {
			t.Errorf("%v = %s, want %s", actions, got, want)
		}
	}
	if (Change{Actions: []string{"create", "delete"}}).Action() != Replace {
		t.Error("create_before_destroy is a replacement too")
	}
}

func TestParse(t *testing.T) {
	p, err := Parse([]byte(`{"format_version":"1.2","resource_changes":[
		{"address":"a.b","mode":"managed","change":{"actions":["create"]}},
		{"address":"data.c.d","mode":"data","change":{"actions":["read"]}},
		{"address":"e.f","mode":"managed","change":{"actions":["delete","create"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	s := p.Summary()
	if s[Create] != 1 || s[Replace] != 1 || s[Read] != 0 {
		t.Fatalf("summary %v", s)
	}
	if _, err := Parse([]byte(`{"values":{}}`)); err == nil {
		t.Error("state JSON must be rejected")
	}
	if _, err := Parse([]byte(`{`)); err == nil {
		t.Error("invalid JSON must be rejected")
	}
}

func TestAttrHelpers(t *testing.T) {
	obj := map[string]any{
		"ingress": []any{map[string]any{"from_port": 22.0, "cidr_blocks": []any{"0.0.0.0/0", 1.0}}},
		"flag":    true,
		"name":    "x",
	}
	if n, ok := Number(obj, "ingress", 0, "from_port"); !ok || n != 22 {
		t.Errorf("Number = %v %v", n, ok)
	}
	if s := Strings(obj, "ingress", 0, "cidr_blocks"); len(s) != 1 || s[0] != "0.0.0.0/0" {
		t.Errorf("Strings = %v", s)
	}
	if b, ok := Bool(obj, "flag"); !ok || !b {
		t.Error("Bool")
	}
	if Attr(obj, "ingress", 5) != nil || Attr(obj, "name", "x") != nil || Attr(obj, 1.5) != nil {
		t.Error("out of range and type mismatches must return nil")
	}
	if String(obj, "name") != "x" || String(obj, "missing") != "" {
		t.Error("String")
	}
	if got := FormatPath([]any{"ingress", 0.0, "cidr_blocks"}); got != "ingress[0].cidr_blocks" {
		t.Errorf("FormatPath = %q", got)
	}
}
