//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

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
#include <unistd.h>

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
typedef int (*amx_list_fn)(uint32_t, uint32_t, void *, int);
typedef int (*amx_info_fn)(int, int, uint64_t, void *, int);
typedef int (*amx_path_fn)(audit_token_t *, void *, uint32_t);
typedef int (*amx_signal_fn)(audit_token_t *, int);
static amx_list_fn amx_list;
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
 amx_list = (amx_list_fn)dlsym(RTLD_DEFAULT, "proc_listpids");
 amx_info = (amx_info_fn)dlsym(RTLD_DEFAULT, "proc_pidinfo");
 amx_path = (amx_path_fn)dlsym(RTLD_DEFAULT, "proc_pidpath_audittoken");
 amx_signal = (amx_signal_fn)dlsym(RTLD_DEFAULT, "proc_signal_with_audittoken");
 if (!amx_system_symbol((void *)amx_list) || !amx_system_symbol((void *)amx_info) || !amx_system_symbol((void *)amx_path) ||
     !amx_system_symbol((void *)amx_signal)) return ENOTSUP;
 int translated = 0;
 size_t size = sizeof(translated);
 if (sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0) == 0) {
  if (size != sizeof(translated) || translated != 0) return ENOTSUP;
 } else if (errno != ENOENT) return ENOTSUP;
 return 0;
}
static long amx_sdk(void) { return __MAC_OS_X_VERSION_MAX_ALLOWED; }
// A full buffer may hide further candidates, so it is always refused.
static int amx_candidates(uint32_t uid, int *pids, size_t capacity, size_t *count) {
 if (!amx_list || capacity != 4096) return EINVAL;
 size_t bytes = capacity * sizeof(*pids);
 memset(pids, 0, bytes);
 int n = amx_list(PROC_UID_ONLY, uid, pids, (int)bytes);
 if (n <= 0 || (size_t)n >= bytes || (size_t)n % sizeof(*pids) != 0) return EPROTO;
 *count = (size_t)n / sizeof(*pids);
 for (size_t i = 0; i < *count; i++) {
  if (pids[i] <= 0) return EPROTO;
 }
 return 0;
}

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
// This diagnostic records compiler layout and one exact own-process query.
// It does not enroll an SDK or construct process authority.
struct amx_layout_evidence {
 size_t bsd_size, unique_size, combined_size, unique_offset, version_offset;
 int selector, returned_size, identity_valid;
};
static void amx_self_layout(struct amx_layout_evidence *out) {
 memset(out, 0, sizeof(*out));
 out->bsd_size = sizeof(struct proc_bsdinfo);
 out->unique_size = sizeof(struct amx_unique);
 out->combined_size = sizeof(struct amx_combined);
 out->unique_offset = offsetof(struct amx_combined, unique);
 out->version_offset = offsetof(struct amx_unique, version);
 out->selector = 18;
 if (!amx_info) return;
 struct amx_combined value;
 memset(&value, 0, sizeof(value));
 int pid = getpid();
 out->returned_size = amx_info(pid, out->selector, 0, &value, sizeof(value));
 out->identity_valid = out->returned_size == sizeof(value) &&
  value.bsd.pbi_pid == pid && value.unique.unique != 0 && value.unique.version != 0 &&
  value.bsd.pbi_status != 0 && value.bsd.pbi_status != 5;
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
	"errors"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

type identity struct {
	PID, ParentPID, Version int32
	UID, RealUID, Status    uint32
	Unique, ParentUnique    uint64
}

var nativeAdmissionOnce sync.Once
var nativeAdmissionCode C.int

func nativeProbeAdmission() (string, int64, error) {
	nativeAdmissionOnce.Do(func() {
		nativeAdmissionCode = C.amx_admit()
	})
	if nativeAdmissionCode != 0 {
		return "", 0, errors.New("native_api_or_translation_refused")
	}
	version, err := unix.Sysctl("kern.osproductversion")
	sdk := int64(C.amx_sdk())
	if err != nil {
		return "", sdk, errors.New("native_os_or_sdk_unenrolled")
	}
	return version, sdk, nil
}

func nativeAdmission() (string, int64, error) {
	version, sdk, err := nativeProbeAdmission()
	if err != nil {
		return "", sdk, err
	}
	major, parseErr := strconv.Atoi(strings.Split(version, ".")[0])
	if parseErr != nil || (major != 15 && major != 26) ||
		!((sdk >= 150000 && sdk < 160000) || (sdk >= 260000 && sdk < 270000)) {
		return "", sdk, errors.New("native_os_or_sdk_unenrolled")
	}
	return version, sdk, nil
}

type nativeLayoutEvidence struct {
	bsdSize, uniqueSize, combinedSize, uniqueOffset, versionOffset uint64
	selector, returnedSize                                         int
	identityValid                                                  bool
}

func nativeSelfLayout() nativeLayoutEvidence {
	var raw C.struct_amx_layout_evidence
	C.amx_self_layout(&raw)
	return nativeLayoutEvidence{
		bsdSize: uint64(raw.bsd_size), uniqueSize: uint64(raw.unique_size),
		combinedSize: uint64(raw.combined_size), uniqueOffset: uint64(raw.unique_offset),
		versionOffset: uint64(raw.version_offset), selector: int(raw.selector),
		returnedSize: int(raw.returned_size), identityValid: raw.identity_valid != 0,
	}
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
	return parseNativeArguments(raw)
}

func identitySignal(id identity, signal int) error {
	code := C.amx_send(C.int(id.PID), C.int32_t(id.Version), C.int(signal))
	if code != 0 {
		return unix.Errno(code)
	}
	return nil
}

// nativeCandidates reads minimal identities before core inspects arguments or paths.
func nativeCandidates(uid uint32, creationParentUnique uint64, admission admissionCheck) ([]identity, error) {
	if creationParentUnique == 0 {
		return nil, errors.New("native_candidate_parent_invalid")
	}
	if admission == nil {
		return nil, errors.New("native_candidate_admission_invalid")
	}
	if err := admission.check(); err != nil {
		return nil, err
	}
	var pids [4096]C.int
	defer clear(pids[:])
	var count C.size_t
	if C.amx_candidates(C.uint32_t(uid), &pids[0], C.size_t(len(pids)), &count) != 0 {
		return nil, errors.New("native_candidates_unavailable")
	}
	candidates := make([]identity, 0)
	for _, pid := range pids[:int(count)] {
		id, err := observe(int(pid))
		if err != nil {
			return nil, errors.New("native_candidate_identity_unavailable")
		}
		if id.UID == uid && id.RealUID == uid && id.ParentUnique == creationParentUnique {
			candidates = append(candidates, id)
		}
	}
	return candidates, nil
}
