import pathlib,hashlib,json,difflib,subprocess
base=pathlib.Path('/mnt/c/Users/RyanHelms/.cache/agentmux-governance/p02-mac-ci-f520')
repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux')
rows=[]
for rel,fn in [('platform/privatefs/access_darwin.go','agentmux_private_acl_safe'),('platform/runtime/acl_darwin.go','agentmux_acl_safe')]:
 old=(repo/rel).read_bytes(); text=old.decode().replace('\r\n','\n')
 text=text.replace('#include <sys/types.h>','#include <sys/types.h>\n#include <sys/stat.h>\n#include <fcntl.h>')
 text=text.replace('MNT_IGNORE_OWNERS)', 'MNT_IGNORE_OWNERSHIP)')
 text=text.replace('    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);\n    if (acl == NULL) return 0;\n    int safe = 0;', '''    // Read absence and ACL content from one successful held-descriptor query.
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
        acl == NULL || acl == _FILESEC_REMOVE_ACL) goto done;''')
 text=text.replace('    if (acl_free(acl) != 0) safe = 0;\n    return safe;', '''    if (acl != NULL && acl != _FILESEC_REMOVE_ACL && acl_free(acl) != 0) safe = 0;
    filesec_free(security);
    return safe;''')
 after=text.encode(); name=pathlib.Path(rel).stem
 (base/(name+'-before.go')).write_bytes(old);(base/(name+'-after.go')).write_bytes(after)
 (base/(name+'-repair.diff')).write_text(''.join(difflib.unified_diff(old.decode().splitlines(True),text.splitlines(True),fromfile=rel+' before',tofile=rel+' after')))
 rows.append({'path':rel,'before':hashlib.sha256(old).hexdigest(),'after':hashlib.sha256(after).hexdigest(),'function':fn})
(base/'repair-source-pins.json').write_text(json.dumps(rows,indent=2)+'\n')
print(json.dumps(rows))