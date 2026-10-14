package launcher

import (
	"os"
	"strings"
)

// dockerEnvironment removes ambient Compose behavior and endpoint selection.
// Docker config/auth discovery, PATH and host interoperability remain unchanged.
// The adapter separately verifies its explicitly selected context and endpoint.
func dockerEnvironment() []string {
	result := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		key = strings.ToUpper(key)
		if strings.HasPrefix(key, "COMPOSE_") || key == "DOCKER_HOST" || key == "DOCKER_CONTEXT" {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "COMPOSE_REMOVE_ORPHANS=0", "COMPOSE_DISABLE_ENV_FILE=1")
}
