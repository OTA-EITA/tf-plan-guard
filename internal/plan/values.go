package plan

import "fmt"

// Attr reads a nested attribute such as Attr(obj, "ingress") or
// Attr(obj, "server_side_encryption_configuration", 0, "rule").
func Attr(obj map[string]any, path ...any) any {
	var cur any = obj
	for _, p := range path {
		switch key := p.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur = m[key]
		case int:
			l, ok := cur.([]any)
			if !ok || key >= len(l) {
				return nil
			}
			cur = l[key]
		default:
			return nil
		}
	}
	return cur
}

// Bool returns the attribute as a bool and whether it was set.
func Bool(obj map[string]any, path ...any) (bool, bool) {
	b, ok := Attr(obj, path...).(bool)
	return b, ok
}

// String returns the attribute as a string, or "".
func String(obj map[string]any, path ...any) string {
	s, _ := Attr(obj, path...).(string)
	return s
}

// List returns the attribute as a list, or nil.
func List(obj map[string]any, path ...any) []any {
	l, _ := Attr(obj, path...).([]any)
	return l
}

// Strings returns a list attribute as strings, skipping non-strings.
func Strings(obj map[string]any, path ...any) []string {
	var out []string
	for _, v := range List(obj, path...) {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Number returns a numeric attribute (JSON numbers decode as float64).
func Number(obj map[string]any, path ...any) (float64, bool) {
	n, ok := Attr(obj, path...).(float64)
	return n, ok
}

// FormatPath renders a replace path such as ["engine_version"] or ["ingress", 0].
func FormatPath(p []any) string {
	out := ""
	for i, seg := range p {
		switch v := seg.(type) {
		case string:
			if i > 0 {
				out += "."
			}
			out += v
		case float64:
			out += fmt.Sprintf("[%d]", int(v))
		}
	}
	return out
}
