//go:build linux || darwin

package protocol

// Role credentials and public server trust use the same held-descriptor access
// checks. A private leaf alone cannot protect a writable enclosing directory.
func readPrivateFile(path string) ([]byte, error) {
	return readPrivateDescriptorFile(path, "kernel_credential")
}
