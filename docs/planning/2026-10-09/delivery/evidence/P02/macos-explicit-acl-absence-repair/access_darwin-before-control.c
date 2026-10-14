
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define MNT_LOCAL 0x1000
#define MNT_IGNORE_OWNERSHIP 0x200000
#define ACL_MAX_ENTRIES 128
#define ACL_EXTENDED_ALLOW 1
#define ACL_EXTENDED_DENY 2
#define ACL_TYPE_EXTENDED 256
#define FILESEC_ACL 5
#define _FILESEC_REMOVE_ACL ((void*)1)
#define ACL_WRITE_DATA 4
#define ACL_APPEND_DATA 32
#define ACL_DELETE 16
#define ACL_DELETE_CHILD 64
#define ACL_WRITE_ATTRIBUTES 256
#define ACL_WRITE_EXTATTRIBUTES 1024
#define ACL_WRITE_SECURITY 4096
#define ACL_CHANGE_OWNER 8192
struct stat { int unused; };
struct statfs { int f_flags; int f_owner; char f_fstypename[8]; };
typedef void *acl_t;typedef void *acl_entry_t;typedef void *acl_permset_t;typedef void *filesec_t;typedef int acl_perm_t;typedef int acl_tag_t;
static int mode,securityFrees,aclFrees;
static int fstatfs(int fd, struct statfs *s){if(fd!=7)return -1;s->f_flags=mode==15?0:MNT_LOCAL;if(mode==16)s->f_flags|=MNT_IGNORE_OWNERSHIP;s->f_owner=0;strcpy(s->f_fstypename,"apfs");return 0;}
static filesec_t filesec_init(void){return mode==1?NULL:(void*)32;}
static int fstatx_np(int fd, struct stat *s,filesec_t f){(void)s;if(fd!=7||f!=(void*)32)return -1;return mode==2?-1:0;}
static int filesec_query_property(filesec_t f,int p,int *present){if(f!=(void*)32||p!=5)return -1;if(mode==3)return -1;*present=mode==0?0:32;return 0;}
static int filesec_get_property(filesec_t f,int p,void *out){if(f!=(void*)32||p!=5)return -1;*(acl_t*)out=mode==5?NULL:mode==6?_FILESEC_REMOVE_ACL:(void*)64;return mode==4?-1:0;}
static void filesec_free(filesec_t f){if(f==(void*)32)securityFrees++;}
static acl_t acl_get_fd_np(int fd,int t){(void)fd;(void)t;return mode==0?NULL:(void*)64;}
static int acl_valid(acl_t a){return a!=(void*)64||mode==7?-1:0;}
static int acl_get_entry(acl_t a,int i,acl_entry_t *e){if(a!=(void*)64)return -1;if(mode==13){errno=EIO;return -1;}if((mode==8||mode==9||mode==10||mode==11||mode==12||mode==14)&&i==0){*e=(void*)80;return 0;}errno=EINVAL;return -1;}
static int acl_get_tag_type(acl_entry_t e,acl_tag_t *t){if(e!=(void*)80)return -1;*t=mode==8?ACL_EXTENDED_DENY:mode==11?99:ACL_EXTENDED_ALLOW;return mode==12?-1:0;}
static int acl_get_permset(acl_entry_t e,acl_permset_t *p){if(e!=(void*)80)return -1;*p=(void*)96;return 0;}
static int acl_get_perm_np(acl_permset_t p,acl_perm_t bit){if(p!=(void*)96)return -1;if(mode==14)return -1;return mode==10&&bit==ACL_WRITE_DATA?1:0;}
static int acl_free(void *a){if(a==(void*)64)aclFrees++;return mode==17?-1:0;}


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
int main(void){mode=0;int private=1;int got=agentmux_private_acl_safe(7, private);printf("absent_acl_admitted=%d\n",got);return got==1?0:1;}