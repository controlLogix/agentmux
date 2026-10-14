//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -ldl
#include <AvailabilityMacros.h>
#include <dlfcn.h>
#include <errno.h>
#include <libproc.h>
#include <mach/message.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>

// Compatibility layout reviewed against Apple xnu-11215.81.4,
// d4514f0bc1d3f944c22d92e68b646ac3fb40d452, proc_info_private.h.
// This is a private ABI assumption, not an SDK support claim. Exact returned
// sizes and native controls are required before this probe can qualify anything.
struct amx_unique {
 uint8_t uuid[16];
 uint64_t unique;
 uint64_t parent_unique;
 int32_t version;
 uint32_t reserved2;
 uint64_t reserved3;
 uint64_t reserved4;
};
struct amx_combined { struct proc_bsdinfo bsd; struct amx_unique unique; };
_Static_assert(sizeof(struct amx_unique) == 56, "unsupported unique ABI");
_Static_assert(offsetof(struct amx_unique, version) == 32, "unsupported version ABI");
_Static_assert(offsetof(struct amx_combined, unique) == sizeof(struct proc_bsdinfo), "unsupported combined ABI");

struct amx_identity {
 int32_t pid, ppid, version;
 uint32_t uid, ruid, status;
 uint64_t unique, parent_unique;
};
typedef int (*amx_info_fn)(int, int, uint64_t, void *, int);
typedef int (*amx_path_fn)(audit_token_t *, void *, uint32_t);
typedef int (*amx_signal_fn)(audit_token_t *, int);
static amx_info_fn amx_info;
static amx_path_fn amx_path;
static amx_signal_fn amx_signal;

static int amx_system_symbol(void *symbol) {
 Dl_info info;
 if (!symbol || !dladdr(symbol, &info) || !info.dli_fname) return 0;
 return !strcmp(info.dli_fname, "/usr/lib/system/libsystem_kernel.dylib") ||
        !strcmp(info.dli_fname, "/usr/lib/system/libsystem_c.dylib") ||
        !strcmp(info.dli_fname, "/usr/lib/libSystem.B.dylib") ||
        !strcmp(info.dli_fname, "/usr/lib/libproc.dylib");
}
static int amx_admit(void) {
 amx_info = (amx_info_fn)dlsym(RTLD_DEFAULT, "proc_pidinfo");
 amx_path = (amx_path_fn)dlsym(RTLD_DEFAULT, "proc_pidpath_audittoken");
 amx_signal = (amx_signal_fn)dlsym(RTLD_DEFAULT, "proc_signal_with_audittoken");
 if (!amx_system_symbol((void *)amx_info) || !amx_system_symbol((void *)amx_path) ||
     !amx_system_symbol((void *)amx_signal)) return ENOTSUP;
 int translated = 0;
 size_t size = sizeof(translated);
 if (sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0) == 0) {
  if (size != sizeof(translated) || translated != 0) return ENOTSUP;
 } else if (errno != ENOENT) return ENOTSUP;
 return 0;
}
static long amx_sdk(void) { return __MAC_OS_X_VERSION_MAX_ALLOWED; }
static int amx_observe(int pid, struct amx_identity *out) {
 if (!amx_info || pid <= 0) return EINVAL;
 struct amx_combined value;
 memset(&value, 0, sizeof(value));
 // Selector 18 and this exact layout belong to the pinned private ABI above.
 int n = amx_info(pid, 18, 0, &value, sizeof(value));
 if (n != sizeof(value)) return n < 0 ? errno : EPROTO;
 if (value.bsd.pbi_pid != pid || value.unique.unique == 0 || value.unique.version == 0 ||
     value.bsd.pbi_status == 0 || value.bsd.pbi_status == 5) return ESRCH;
 out->pid = pid; out->ppid = value.bsd.pbi_ppid;
 out->uid = value.bsd.pbi_uid; out->ruid = value.bsd.pbi_ruid;
 out->status = value.bsd.pbi_status; out->version = value.unique.version;
 out->unique = value.unique.unique; out->parent_unique = value.unique.parent_unique;
 return 0;
}
// This is a target identifier, not an authenticated credential token. The
// pinned kernel uses PID/version and checks the real caller's permission.
static audit_token_t amx_identifier(int pid, int32_t version) {
 audit_token_t value = {{0}};
 value.val[5] = (uint32_t)pid; value.val[7] = (uint32_t)version;
 return value;
}
static int amx_image_path(int pid, int32_t version, char *out, size_t size) {
 if (!amx_path || size < PROC_PIDPATHINFO_MAXSIZE) return EINVAL;
 audit_token_t target = amx_identifier(pid, version);
 memset(out, 0, size);
 int n = amx_path(&target, out, (uint32_t)size);
 if (n <= 0 || n >= size || !memchr(out, 0, size)) return n <= 0 ? errno : EPROTO;
 return 0;
}
static int amx_send(int pid, int32_t version, int signal_number) {
 if (!amx_signal) return ENOTSUP;
 audit_token_t target = amx_identifier(pid, version);
 return amx_signal(&target, signal_number);
}
static void amx_wipe(void *buffer, size_t size) {
 volatile unsigned char *bytes = (volatile unsigned char *)buffer;
 while (size--) *bytes++ = 0;
}
static int amx_arguments(int pid, void **result, size_t *length) {
 int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
 size_t size = 256 * 1024;
 void *buffer = calloc(1, size);
 if (!buffer) return ENOMEM;
 if (sysctl(mib, 3, buffer, &size, NULL, 0) || size < sizeof(int) || size > 256 * 1024) {
  int e = errno ? errno : EPROTO;
  amx_wipe(buffer, 256 * 1024); free(buffer); return e;
 }
 *result = buffer; *length = size; return 0;
}
static void amx_free_arguments(void *buffer) {
 if (buffer) { amx_wipe(buffer, 256 * 1024); free(buffer); }
}
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

type identity struct {
	PID, ParentPID, Version int32
	UID, RealUID, Status    uint32
	Unique, ParentUnique    uint64
}

func nativeAdmission() (string, int64, error) {
	if C.amx_admit() != 0 {
		return "", 0, errors.New("native_api_or_translation_refused")
	}
	version, err := unix.Sysctl("kern.osproductversion")
	major, parseErr := strconv.Atoi(strings.Split(version, ".")[0])
	sdk := int64(C.amx_sdk())
	if err != nil || parseErr != nil || (major != 15 && major != 26) ||
		!((sdk >= 150000 && sdk < 160000) || (sdk >= 260000 && sdk < 270000)) {
		return "", sdk, errors.New("native_os_or_sdk_unenrolled")
	}
	return version, sdk, nil
}

func observe(pid int) (identity, error) {
	var raw C.struct_amx_identity
	if C.amx_observe(C.int(pid), &raw) != 0 {
		return identity{}, errors.New("native_identity_unavailable")
	}
	return identity{int32(raw.pid), int32(raw.ppid), int32(raw.version), uint32(raw.uid),
		uint32(raw.ruid), uint32(raw.status), uint64(raw.unique), uint64(raw.parent_unique)}, nil
}

func nativePath(id identity) (string, error) {
	var raw [4096]byte
	if C.amx_image_path(C.int(id.PID), C.int32_t(id.Version), (*C.char)(unsafe.Pointer(&raw[0])), C.size_t(len(raw))) != 0 {
		return "", errors.New("version_bound_image_path_unavailable")
	}
	end := bytes.IndexByte(raw[:], 0)
	if end <= 0 {
		return "", errors.New("version_bound_image_path_invalid")
	}
	return string(raw[:end]), nil
}

func nativeArguments(id identity) ([]string, error) {
	var pointer unsafe.Pointer
	var size C.size_t
	if C.amx_arguments(C.int(id.PID), &pointer, &size) != 0 {
		return nil, errors.New("native_arguments_unavailable")
	}
	defer C.amx_free_arguments(pointer)
	raw := C.GoBytes(pointer, C.int(size))
	defer clear(raw)
	count := int(binary.NativeEndian.Uint32(raw[:4]))
	if count < 1 || count > 32 {
		return nil, errors.New("native_argument_count_invalid")
	}
	remaining := raw[4:]
	end := bytes.IndexByte(remaining, 0)
	if end < 1 {
		return nil, errors.New("native_argument_header_invalid")
	}
	remaining = bytes.TrimLeft(remaining[end+1:], "\x00")
	args := make([]string, 0, count)
	for range count {
		end = bytes.IndexByte(remaining, 0)
		if end < 1 || end > 4096 {
			return nil, errors.New("native_argument_shape_invalid")
		}
		args = append(args, string(remaining[:end]))
		remaining = remaining[end+1:]
	}
	return args, nil
}

func identitySignal(id identity, signal int) error {
	code := C.amx_send(C.int(id.PID), C.int32_t(id.Version), C.int(signal))
	if code != 0 {
		return unix.Errno(code)
	}
	return nil
}
