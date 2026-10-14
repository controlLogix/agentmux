//go:build darwin && cgo

package runtime

/*
#include <sys/types.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <unistd.h>
#include <string.h>

// This flavor accepts only DTYPE_PIPE. Named FIFOs are vnode descriptors.
// The kernel holds the fileproc while it reads this exact self-owned fd.
static int agentmux_receipt_anonymous_pipe(int fd) {
 struct pipe_fdinfo info;
 memset(&info, 0, sizeof(info));
 int size = proc_pidfdinfo(getpid(), PROC_PIDFDPIPEINFO, fd, &info, sizeof(info));
 return size == sizeof(info) && info.pipeinfo.pipe_handle != 0 &&
  info.pipeinfo.pipe_peerhandle != 0;
}
*/
import "C"

import "golang.org/x/sys/unix"

func receiptAnonymousPipe(fd int) bool {
 return C.agentmux_receipt_anonymous_pipe(C.int(fd)) == 1
}

// Darwin reports synthetic0660 metadata for anonymous pipes. That metadata
// grants no ownership; the native descriptor type and creator inheritance do.
func bootstrapReceiptDescriptorValid(fd int, info *unix.Stat_t, flags int) bool {
 return info != nil && info.Mode&unix.S_IFMT == unix.S_IFIFO &&
  info.Mode&07777 == 0660 && info.Dev == 0 && info.Rdev == 0 && info.Nlink == 0 &&
  flags&unix.O_ACCMODE == unix.O_WRONLY && receiptAnonymousPipe(fd)
}
