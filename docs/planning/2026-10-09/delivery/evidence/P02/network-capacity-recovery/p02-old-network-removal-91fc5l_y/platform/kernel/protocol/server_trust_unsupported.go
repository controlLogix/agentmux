//go:build !linux && !darwin

package protocol

import "errors"

func readServerTrustFile(string) ([]byte, error) {
	return nil, errors.New("kernel_server_trust_platform_unqualified")
}
