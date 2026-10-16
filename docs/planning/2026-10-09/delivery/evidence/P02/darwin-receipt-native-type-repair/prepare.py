import pathlib,hashlib,json,difflib
b=pathlib.Path('/mnt/c/Users/RyanHelms/.cache/agentmux-governance/p02-darwin-receipt-pipe-controls');repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');p=b/'src/platform/runtime';p.mkdir(parents=True,exist_ok=True)
old=(repo/'platform/runtime/bootstrap_receipt.go').read_bytes();t=old.decode().replace('\r\n','\n');t=t.replace('info.Mode&unix.S_IFMT != unix.S_IFIFO || info.Mode&0077 != 0 || info.Uid != uint32(os.Geteuid()) || flags&unix.O_ACCMODE != unix.O_WRONLY','!bootstrapReceiptDescriptorValid(fd, &info, flags)');(b/'bootstrap_receipt-before.go').write_bytes(old);(p/'bootstrap_receipt.go').write_text(t)
linux='''//go:build linux

package runtime

import (
 "os"
 "golang.org/x/sys/unix"
)

// Linux preserves its existing inherited-pipe metadata admission.
func bootstrapReceiptDescriptorValid(_ int, info *unix.Stat_t, flags int) bool {
 return info != nil && info.Mode&unix.S_IFMT == unix.S_IFIFO && info.Mode&0077 == 0 && info.Uid == uint32(os.Geteuid()) && flags&unix.O_ACCMODE == unix.O_WRONLY
}
'''
(p/'bootstrap_receipt_descriptor_linux.go').write_text(linux)
darwin='''//go:build darwin && cgo

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
'''
(p/'bootstrap_receipt_descriptor_darwin.go').write_text(darwin)
(p/'bootstrap_receipt_descriptor_darwin_nocgo.go').write_text('''//go:build darwin && !cgo

package runtime

import "golang.org/x/sys/unix"

// Native pipe identity is required; metadata alone cannot qualify the writer.
func bootstrapReceiptDescriptorValid(_ int, _ *unix.Stat_t, _ int) bool { return false }
''')
(p/'bootstrap_receipt_descriptor_linux_test.go').write_text('''//go:build linux

package runtime

import (
 "os"
 "testing"
 "golang.org/x/sys/unix"
)

func TestReceiptLinuxDescriptorPreservesAdmission(t *testing.T) {
 reader, writer, err := os.Pipe()
 if err != nil { t.Fatal("owned pipe unavailable") }
 defer reader.Close(); defer writer.Close()
 var stat unix.Stat_t
 flags, err := unix.FcntlInt(writer.Fd(), unix.F_GETFL, 0)
 if err != nil || unix.Fstat(int(writer.Fd()), &stat) != nil { t.Fatal("owned descriptor unavailable") }
 if !bootstrapReceiptDescriptorValid(int(writer.Fd()), &stat, flags) { t.Fatal("genuine writer refused") }
 for _, fault := range []string{"mode", "owner", "type", "read", "readwrite", "nil"} {
  t.Run(fault, func(t *testing.T) {
   changed := stat; chosen := flags; ptr := &changed
   switch fault { case "mode": changed.Mode |= 0040; case "owner": changed.Uid++; case "type": changed.Mode = unix.S_IFREG|0600; case "read": chosen = unix.O_RDONLY; case "readwrite": chosen = unix.O_RDWR; case "nil": ptr=nil }
   if bootstrapReceiptDescriptorValid(int(writer.Fd()),ptr,chosen) { t.Fatal("invalid writer admitted") }
  })
 }
}
''')
# Native-only controls are authored, not executed locally.
(p/'bootstrap_receipt_descriptor_darwin_test.go').write_text('''//go:build darwin && cgo

package runtime

import (
 "os"
 "path/filepath"
 "testing"
 "golang.org/x/sys/unix"
)

func TestDarwinReceiptRequiresActualAnonymousWritePipe(t *testing.T) {
 reader, writer, err := os.Pipe()
 if err != nil { t.Fatal("owned pipe unavailable") }
 defer reader.Close(); defer writer.Close()
 check := func(fd int) bool { var s unix.Stat_t; flags,e:=unix.FcntlInt(uintptr(fd),unix.F_GETFL,0); return e==nil && unix.Fstat(fd,&s)==nil && bootstrapReceiptDescriptorValid(fd,&s,flags) }
 if !check(int(writer.Fd())) || check(int(reader.Fd())) { t.Fatal("actual pipe direction refused or read end admitted") }
 if !receiptAnonymousPipe(int(reader.Fd())) { t.Fatal("native anonymous type query failed") }
 file,err:=os.CreateTemp(t.TempDir(),"regular")
 if err!=nil { t.Fatal("owned file unavailable") }; defer file.Close()
 if receiptAnonymousPipe(int(file.Fd())) || check(int(file.Fd())) { t.Fatal("regular file admitted") }
 sockets,err:=unix.Socketpair(unix.AF_UNIX,unix.SOCK_STREAM,0)
 if err!=nil { t.Fatal("owned socket unavailable") }; defer unix.Close(sockets[0]);defer unix.Close(sockets[1])
 if receiptAnonymousPipe(sockets[0]) || check(sockets[0]) { t.Fatal("socket admitted") }
 path:=filepath.Join(t.TempDir(),"named-fifo")
 if unix.Mkfifo(path,0600)!=nil { t.Fatal("owned FIFO unavailable") }
 rd,err:=unix.Open(path,unix.O_RDONLY|unix.O_NONBLOCK,0)
 if err!=nil { t.Fatal("owned FIFO reader unavailable") };defer unix.Close(rd)
 wr,err:=unix.Open(path,unix.O_WRONLY|unix.O_NONBLOCK,0)
 if err!=nil { t.Fatal("owned FIFO writer unavailable") };defer unix.Close(wr)
 if receiptAnonymousPipe(wr) || check(wr) { t.Fatal("named FIFO admitted") }
 if unix.Fchmod(wr,0660)!=nil || receiptAnonymousPipe(wr) || check(wr) { t.Fatal("named FIFO mode granted anonymous identity") }
}
''')
(p/'bootstrap_receipt_descriptor_darwin_nocgo_test.go').write_text('''//go:build darwin && !cgo

package runtime

import (
 "testing"
 "golang.org/x/sys/unix"
)

func TestDarwinReceiptWithoutCGORefuses(t *testing.T) {
 s:=unix.Stat_t{Mode: unix.S_IFIFO|0660}
 if bootstrapReceiptDescriptorValid(3,&s,unix.O_WRONLY) { t.Fatal("native identity missing but writer admitted") }
}
''')
(b/'candidate.diff').write_text(''.join(difflib.unified_diff(old.decode().splitlines(True),t.splitlines(True),fromfile='bootstrap_receipt.go before',tofile='bootstrap_receipt.go candidate')))
print(json.dumps({str(x.relative_to(b)):hashlib.sha256(x.read_bytes()).hexdigest() for x in p.glob('*.go')}))