//go:build darwin && cgo

package privatefs

/*
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <errno.h>

// Apple's indexed ACL iterator returns zero for an entry and EINVAL at end.
// Validate first so malformed ACL data cannot look like an empty ACL.
static int agentmux_private_acl_safe(int fd, int private_object) {
    struct statfs mount;
    if (fstatfs(fd, &mount) != 0 || (mount.f_flags & MNT_LOCAL) == 0 ||
        (mount.f_flags & MNT_IGNORE_OWNERSHIP) != 0) return 0;
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (acl == NULL) return 0;
    int safe = 0;
    if (acl_valid(acl) != 0) goto done;
    for (int i = 0; i <= ACL_MAX_ENTRIES; i++) {
        acl_entry_t entry;
        errno = 0;
        if (acl_get_entry(acl, i, &entry) != 0) {
            safe = errno == EINVAL;
            goto done;
        }
        if (i == ACL_MAX_ENTRIES) goto done;
        acl_tag_t tag;
        if (acl_get_tag_type(entry, &tag) != 0) goto done;
        if (tag == ACL_EXTENDED_DENY) continue;
        if (tag != ACL_EXTENDED_ALLOW || private_object) goto done;
        acl_permset_t permissions;
        if (acl_get_permset(entry, &permissions) != 0) goto done;
        const acl_perm_t mutations[] = {ACL_WRITE_DATA, ACL_APPEND_DATA,
            ACL_DELETE, ACL_DELETE_CHILD, ACL_WRITE_ATTRIBUTES,
            ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER};
        for (unsigned int j = 0; j < sizeof(mutations)/sizeof(mutations[0]); j++) {
            if (acl_get_perm_np(permissions, mutations[j]) != 0) goto done;
        }
    }
done:
    if (acl_free(acl) != 0) safe = 0;
    return safe;
}
*/
import "C"

func checkNativeDescriptor(fd uintptr, kind AccessKind) error {
	private := 0
	if kind == PrivateObject {
		private = 1
	}
	if C.agentmux_private_acl_safe(C.int(fd), C.int(private)) != 1 {
		return ErrAccessDenied
	}
	return nil
}
