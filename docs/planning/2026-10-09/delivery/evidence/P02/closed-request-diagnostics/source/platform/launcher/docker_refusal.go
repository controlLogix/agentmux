package launcher

import (
	"encoding/json"
	"fmt"
)

// Only launcher refusal sites can construct this private type. Its fixed code
// identifies a trusted refusal; a matching arbitrary error string does not.
type dockerRefusalError struct{ code string }

func (e dockerRefusalError) Error() string {
	if len(e.code) == 0 || len(e.code) > 96 {
		return "docker_refusal"
	}
	for _, c := range e.code {
		if c != '_' && (c < 'a' || c > 'z') {
			return "docker_refusal"
		}
	}
	return "docker_" + e.code
}
func (e dockerRefusalError) Format(state fmt.State, _ rune) { fmt.Fprint(state, e.Error()) }
func (e dockerRefusalError) MarshalJSON() ([]byte, error)   { return json.Marshal(e.Error()) }
