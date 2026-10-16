//go:build darwin && cgo && agentmux_darwin_ownership_mount

// Package darwinownershipfixture provides a read-only ACL-property query for
// explicitly selected native ownership-mount tests, not product admission.
package darwinownershipfixture

/*
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

// Do not combine this query with mount policy or infer absence from failure.
// filesec_free has a void return in the SDK: release the sole allocation on
// every path, but do not claim a cleanup-status result that the API lacks.
static int agentmux_fixture_acl_absent(int fd) {
    filesec_t security = filesec_init();
    if (security == NULL) return -1;
    struct stat metadata;
    int present = -1;
    int result = -1;
    if (fstatx_np(fd, &metadata, security) == 0 &&
        filesec_query_property(security, FILESEC_ACL, &present) == 0 &&
        (present == 0 || present == 1)) {
        result = present == 0 ? 1 : 0;
    }
    filesec_free(security);
    return result;
}
*/
import "C"

import (
	"errors"
	"os"
)

// ACLAbsent reports only explicit FILESEC_ACL property absence after successful
// fstatx_np and filesec_query_property calls on the same held descriptor.
// False with no error means the property is present, not that its ACL is safe.
// The caller retains ownership: this helper opens and closes no descriptors.
func ACLAbsent(file *os.File) (bool, error) {
	if file == nil {
		return false, errors.New("ownership_fixture_acl_descriptor_invalid")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return false, errors.New("ownership_fixture_acl_descriptor_invalid")
	}
	result := -1
	if raw.Control(func(fd uintptr) {
		result = int(C.agentmux_fixture_acl_absent(C.int(fd)))
	}) != nil {
		return false, errors.New("ownership_fixture_acl_descriptor_invalid")
	}
	if result < 0 {
		return false, errors.New("ownership_fixture_acl_property_query_failed")
	}
	return result == 1, nil
}
