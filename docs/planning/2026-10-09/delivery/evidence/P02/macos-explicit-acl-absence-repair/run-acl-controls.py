import pathlib,re,subprocess,json,hashlib
b=pathlib.Path('/mnt/c/Users/RyanHelms/.cache/agentmux-governance/p02-mac-ci-f520')
pre=r'''
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
'''
results=[]
for stem,fn,private in [('access_darwin','agentmux_private_acl_safe',True),('acl_darwin','agentmux_acl_safe',False)]:
 for stage in ['before','after']:
  s=(b/(stem+'-'+stage+'.go')).read_text();c=s[s.index('/*')+2:s.index('*/')];c=re.sub(r'^#include.*\n','',c,flags=re.M)
  if stage=='before' and not private:c=c.replace('MNT_IGNORE_OWNERS)','MNT_IGNORE_OWNERSHIP)')
  call=fn+'(7, private)' if private else '('+fn+'(7) && agentmux_mount_safe(7))'
  body='''int main(void){int failures=0;for(mode=0;mode<=17;mode++){for(int private=0;private<=1;private++){securityFrees=aclFrees=0;int got=CALL;int expected=(mode==0||mode==8||(mode==9&&!private));if(!PRIVATE)expected=(mode==0||mode==8||mode==9);if(got!=expected){printf("mode=%d private=%d got=%d expected=%d\\n",mode,private,got,expected);failures++;}if(STAGE&&mode!=1&&mode!=15&&mode!=16&&securityFrees!=1){printf("security_free_count_invalid\\n");failures++;}}}return failures?1:0;}'''.replace('CALL',call).replace('PRIVATE','1' if private else '0').replace('STAGE','1' if stage=='after' else '0')
  # Before controls isolate the actual absent-ACL defect, not unrelated error injection.
  if stage=='before':body=('int main(void){mode=0;int private=1;int got='+call+';printf("absent_acl_admitted=%d\\n",got);return got==1?0:1;}')
  src=b/(stem+'-'+stage+'-control.c');src.write_text(pre+c+body)
  exe=b/(stem+'-'+stage+'-control')
  for name,argv in [('compile',['cc','-std=c11','-Werror=implicit-function-declaration',str(src),'-o',str(exe)]),('run',[str(exe)])]:
   p=subprocess.run(argv,capture_output=True);(b/(stem+'-'+stage+'-'+name+'.stdout')).write_bytes(p.stdout);(b/(stem+'-'+stage+'-'+name+'.stderr')).write_bytes(p.stderr);results.append({'stem':stem,'stage':stage,'kind':name,'argv':argv,'exitCode':p.returncode})
   if name=='compile' and p.returncode:break
(b/'acl-controls.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results))