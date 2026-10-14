//go:build !linux && !darwin

package deployment

func teamReadPrivate(string, string, uint32) ([]byte, error) {
	return nil, teamError("private_platform_unqualified")
}
