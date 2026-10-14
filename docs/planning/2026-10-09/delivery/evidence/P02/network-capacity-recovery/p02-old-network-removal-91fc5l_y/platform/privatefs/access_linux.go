//go:build linux

package privatefs

// Linux caller mode0600/0700 gates mask named-user/group POSIX ACL grants.
// This helper does not replace those existing owner/mode checks.
func checkNativeDescriptor(uintptr, AccessKind) error { return nil }
