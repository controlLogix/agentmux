//go:build darwin && cgo

package runtime

/*
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <errno.h>
#include <string.h>

// Apple returns zero for an entry and EINVAL at the end, unlike Linux ACLs.
// Validate the retrieved ACL first so a bad object cannot look like an empty ACL.
static int agentmux_acl_safe(int fd) {
    // Read absence and ACL content from one successful held-descriptor query.
    // A NULL ACL result alone is never proof that the file has no ACL.
    filesec_t security = filesec_init();
    if (security == NULL) return 0;
    struct stat metadata;
    acl_t acl = NULL;
    int present = 0;
    int safe = 0;
    if (fstatx_np(fd, &metadata, security) != 0 ||
        filesec_query_property(security, FILESEC_ACL, &present) != 0) goto done;
    if (!present) { safe = 1; goto done; }
    if (filesec_get_property(security, FILESEC_ACL, &acl) != 0 ||
        acl == NULL || acl == _FILESEC_REMOVE_ACL) goto done;
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
        if (tag != ACL_EXTENDED_ALLOW) goto done;
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
    if (acl != NULL && acl != _FILESEC_REMOVE_ACL && acl_free(acl) != 0) safe = 0;
    filesec_free(security);
    return safe;
}

static int agentmux_mount_safe(int fd) {
    struct statfs mount;
    if (fstatfs(fd, &mount) != 0) return 0;
    return (mount.f_flags & MNT_LOCAL) != 0 &&
        (mount.f_flags & MNT_IGNORE_OWNERSHIP) == 0 && mount.f_owner == 0 &&
        strcmp(mount.f_fstypename, "apfs") == 0;
}
*/
import "C"

// Native ACL and mount metadata are read from the same admitted descriptor.
// No text parser, principal resolver or permissive unknown result is used.
func darwinDescriptorPolicy(fd int) bool {
	return C.agentmux_acl_safe(C.int(fd)) == 1 && C.agentmux_mount_safe(C.int(fd)) == 1
}
