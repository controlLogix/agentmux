//go:build !linux && !darwin

package protocol

import "errors"

func readPrivateFile(string) ([]byte, error) {
	return nil, errors.New("kernel_credential_platform_unqualified")
}
