package plugins

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// ProfileContext carries explicit display metadata from an admitted profile.
// Project is not an authorization projectId. Neither field grants access.
// A nil context or field stays absent; callers must not infer defaults.
type ProfileContext struct {
	Environment *string `json:"environment,omitempty"`
	Project     *string `json:"project,omitempty"`
}

func validProfileContext(c *ProfileContext) bool {
	if c == nil {
		return true
	}
	if c.Environment == nil && c.Project == nil {
		return false
	}
	for _, value := range []*string{c.Environment, c.Project} {
		if value == nil {
			continue
		}
		if *value == "" || strings.TrimSpace(*value) != *value || len(*value) > 128 || !utf8.ValidString(*value) {
			return false
		}
		for _, r := range *value {
			if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
				return false
			}
		}
	}
	return true
}

func cloneProfileContext(c *ProfileContext) *ProfileContext {
	if c == nil {
		return nil
	}
	out := *c
	if c.Environment != nil {
		value := *c.Environment
		out.Environment = &value
	}
	if c.Project != nil {
		value := *c.Project
		out.Project = &value
	}
	return &out
}
