// Package plan reads the JSON representation of a Terraform (or OpenTofu)
// plan produced by `terraform show -json PLANFILE`.
package plan

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Plan is the subset of the plan JSON format that is inspected.
type Plan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
}

// ResourceChange describes the planned change to one resource instance.
type ResourceChange struct {
	Address      string `json:"address"`
	Mode         string `json:"mode"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	ProviderName string `json:"provider_name"`
	Change       Change `json:"change"`
}

// Change holds the planned actions and the object before and after.
type Change struct {
	Actions      []string       `json:"actions"`
	Before       map[string]any `json:"before"`
	After        map[string]any `json:"after"`
	ReplacePaths [][]any        `json:"replace_paths"`
}

// Action is the effective kind of change.
type Action string

// Effective actions derived from the action list.
const (
	NoOp    Action = "no-op"
	Read    Action = "read"
	Create  Action = "create"
	Update  Action = "update"
	Delete  Action = "delete"
	Replace Action = "replace"
)

// Action collapses the action list: [delete create] and [create delete]
// (create_before_destroy) are both replacements.
func (c Change) Action() Action {
	has := map[string]bool{}
	for _, a := range c.Actions {
		has[a] = true
	}
	switch {
	case has["delete"] && has["create"]:
		return Replace
	case has["delete"]:
		return Delete
	case has["create"]:
		return Create
	case has["update"]:
		return Update
	case has["read"]:
		return Read
	default:
		return NoOp
	}
}

// Parse decodes plan JSON and rejects input that is not a plan, such as
// `terraform show -json` of state instead of a plan file.
func Parse(data []byte) (Plan, error) {
	var p Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("parse plan JSON: %w", err)
	}
	if p.FormatVersion == "" {
		return p, errors.New("not a plan: missing format_version (create it with `terraform show -json PLANFILE`)")
	}
	return p, nil
}

// Summary counts managed resource changes by action, like the plan footer.
func (p Plan) Summary() map[Action]int {
	s := map[Action]int{}
	for _, rc := range p.ResourceChanges {
		if rc.Mode != "managed" {
			continue
		}
		s[rc.Change.Action()]++
	}
	return s
}
