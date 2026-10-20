package plugins

import (
	"crypto/sha256"
	"encoding/hex"
)

type Error struct{ code string }

func (e *Error) Error() string      { return e.code }
func (e *Error) Code() string       { return e.code }
func pluginError(code string) error { return &Error{code: code} }
func checksum(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}
