#include <stddef.h>
#include <string.h>
#include <stdio.h>
#define PROC_PIDFDPIPEINFO 6
struct pipe_fdinfo { struct {unsigned long long pipe_handle,pipe_peerhandle;} pipeinfo; };
static int scenario;
static int getpid(void){return 41;}
static int proc_pidfdinfo(int pid,int fd,int flavor,void *buffer,int size){
 if(pid!=41||flavor!=6||fd!=7)return -1;
 struct pipe_fdinfo *p=buffer;p->pipeinfo.pipe_handle=scenario==3?0:10;p->pipeinfo.pipe_peerhandle=scenario==4?0:11;
 if(scenario==0)return size;if(scenario==1)return -1;if(scenario==2)return size-1;if(scenario==5)return 0;if(scenario==6)return size+1;return size;
}


// This SDK-exported private interface must qualify on each supported native OS/SDK.
// This flavor accepts only DTYPE_PIPE. Named FIFOs are vnode descriptors.
// The kernel holds the fileproc while it reads this exact self-owned fd.
static int agentmux_receipt_anonymous_pipe(int fd) {
 struct pipe_fdinfo info;
 memset(&info, 0, sizeof(info));
 int size = proc_pidfdinfo(getpid(), fd, PROC_PIDFDPIPEINFO, &info, sizeof(info));
 return size == sizeof(info) && info.pipeinfo.pipe_handle != 0 &&
  info.pipeinfo.pipe_peerhandle != 0;
}
int main(void){for(scenario=0;scenario<7;scenario++){int expected=scenario==0;int got=agentmux_receipt_anonymous_pipe(7);if(got!=expected){printf("scenario=%d unexpected_admission\n",scenario);return 1;}}if(agentmux_receipt_anonymous_pipe(8))return 1;puts("8 modeled native-type/result controls passed");return 0;}
