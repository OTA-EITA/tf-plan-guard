package rules

import (
	"encoding/json"
	"strings"
)

// stringList accepts a JSON string or an array of strings, as IAM allows.
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = stringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		*s = nil
		return nil //nolint:nilerr // non-string values (e.g. principal maps) are handled elsewhere
	}
	*s = many
	return nil
}

type statement struct {
	Effect    string          `json:"Effect"`
	Action    stringList      `json:"Action"`
	Resource  stringList      `json:"Resource"`
	Principal json.RawMessage `json:"Principal"`
	Condition json.RawMessage `json:"Condition"`
}

type policyDoc struct {
	Statement json.RawMessage `json:"Statement"`
}

// statements decodes an IAM policy document given as a JSON string. Unknown
// or invalid documents yield no statements rather than an error, because the
// value may still be unknown at plan time.
func statements(doc string) []statement {
	if strings.TrimSpace(doc) == "" {
		return nil
	}
	var p policyDoc
	if err := json.Unmarshal([]byte(doc), &p); err != nil || len(p.Statement) == 0 {
		return nil
	}
	if p.Statement[0] == '{' {
		var st statement
		if json.Unmarshal(p.Statement, &st) != nil {
			return nil
		}
		return []statement{st}
	}
	var sts []statement
	if json.Unmarshal(p.Statement, &sts) != nil {
		return nil
	}
	return sts
}

func (s statement) allows() bool { return strings.EqualFold(s.Effect, "Allow") }

func (s statement) hasCondition() bool {
	c := strings.TrimSpace(string(s.Condition))
	return c != "" && c != "null" && c != "{}"
}

// principalIsAnyone reports Principal "*" or {"AWS": "*"}.
func (s statement) principalIsAnyone() bool {
	var star string
	if json.Unmarshal(s.Principal, &star) == nil {
		return star == "*"
	}
	var m map[string]stringList
	if json.Unmarshal(s.Principal, &m) != nil {
		return false
	}
	for _, v := range m["AWS"] {
		if v == "*" {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// wildcardLevel classifies a policy: 2 = full admin (Action "*"),
// 1 = a whole service on every resource (e.g. "s3:*" on "*"), 0 = scoped.
func wildcardLevel(doc string) (int, string) {
	level, detail := 0, ""
	for _, st := range statements(doc) {
		if !st.allows() {
			continue
		}
		if contains(st.Action, "*") {
			return 2, `Action "*"`
		}
		if contains(st.Resource, "*") {
			for _, a := range st.Action {
				if strings.HasSuffix(a, ":*") {
					level, detail = 1, `Action "`+a+`" on Resource "*"`
				}
			}
		}
	}
	return level, detail
}

// publicPrincipal reports an Allow statement for anyone without conditions.
func publicPrincipal(doc string) bool {
	for _, st := range statements(doc) {
		if st.allows() && st.principalIsAnyone() && !st.hasCondition() {
			return true
		}
	}
	return false
}
