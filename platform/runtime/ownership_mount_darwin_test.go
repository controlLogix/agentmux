//go:build darwin && cgo && agentmux_darwin_ownership_mount

package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/controlLogix/agentmux/platform/internal/darwinownershipfixture"
	"golang.org/x/sys/unix"
)

// Fixture-only Darwin O_SEARCH: SDK26.5 sys/fcntl.h lines162-163 defines
// O_EXEC=0x40000000 and O_SEARCH=(O_EXEC|O_DIRECTORY). x/sys v0.48.0 omits both.
// Search is for ancestors; final directory/file leaves keep read access.
const darwinDirectorySearchOnly = 0x40000000 | unix.O_DIRECTORY

type ownershipMountPin struct {
	Mountpoint string   `json:"mountpoint"`
	Device     string   `json:"device"`
	VolumeFSID [2]int32 `json:"volumeFSID"`
	Dev        int32    `json:"dev"`
	RootInode  uint64   `json:"rootInode"`
	FileInode  uint64   `json:"fileInode"`
	Flags      uint32   `json:"flags"`
}
type ownershipMountManifest struct {
	Version              int               `json:"version"`
	AuthorizedDisposable bool              `json:"authorizedDisposable"`
	Owners               ownershipMountPin `json:"owners"`
	NoOwners             ownershipMountPin `json:"noOwners"`
}

// The external owner provisions two disposable APFS volumes and an ACL-free
// directory (0700) containing "control" (0600, one link), owned by this user.
// AMX_OWNERSHIP_MANIFEST names a canonical private JSON file; its exact bytes
// are pinned by AMX_OWNERSHIP_MANIFEST_SHA256 (lowercase hex, no prefix).
// volumeFSID is the actual kernel volume identity, not an asserted UUID.
// The external attachment receipt must separately bind each device to its image.
// Tests only open, inspect and close resources; the provisioner owns detach.
func ownershipOpen(t *testing.T, path string, directory bool) *os.File {
	t.Helper()
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		t.Fatal("ownership fixture canonical path required")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("ownership fixture root unavailable")
	}
	current := os.NewFile(uintptr(fd), "ownership-fixture-root")
	for i, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		if i < len(strings.Split(strings.TrimPrefix(path, "/"), "/"))-1 {
			flags |= darwinDirectorySearchOnly
		} else if directory {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(int(current.Fd()), part, flags, 0)
		closeErr := current.Close()
		if openErr != nil || closeErr != nil {
			if openErr == nil {
				if os.NewFile(uintptr(next), "ownership-fixture").Close() != nil {
					t.Error("ownership fixture intermediate cleanup failed")
				}
			}
			t.Fatal("ownership fixture no-follow open or cleanup failed")
		}
		current = os.NewFile(uintptr(next), "ownership-fixture")
	}
	t.Cleanup(func() {
		if current.Close() != nil {
			t.Error("ownership fixture descriptor cleanup failed")
		}
	})
	return current
}

func ownershipDecode(data []byte, out *ownershipMountManifest) bool {
	if !utf8.Valid(data) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(reflect.Type) bool
	walk = func(schema reflect.Type) bool {
		token, err := decoder.Token()
		if err != nil || token == nil {
			return false
		}
		switch schema.Kind() {
		case reflect.Struct:
			if token != json.Delim('{') {
				return false
			}
			fields := map[string]reflect.Type{}
			for i := 0; i < schema.NumField(); i++ {
				field := schema.Field(i)
				fields[field.Tag.Get("json")] = field.Type
			}
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				field, exists := fields[name]
				if err != nil || !ok || !exists || seen[name] {
					return false
				}
				seen[name] = true
				if !walk(field) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}') && len(seen) == len(fields)
		case reflect.Array:
			if token != json.Delim('[') {
				return false
			}
			count := 0
			for decoder.More() {
				if count == schema.Len() || !walk(schema.Elem()) {
					return false
				}
				count++
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']') && count == schema.Len()
		case reflect.String:
			_, ok := token.(string)
			return ok
		case reflect.Bool:
			_, ok := token.(bool)
			return ok
		case reflect.Int, reflect.Int32, reflect.Uint32, reflect.Uint64:
			_, ok := token.(json.Number)
			return ok
		default:
			return false
		}
	}
	if !walk(reflect.TypeOf(*out)) {
		return false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return false
	}
	// Typed decoding additionally rejects fractional and out-of-range integers.
	return json.Unmarshal(data, out) == nil
}

// Replace the failed raw fgetattrlist/parser approach preserved in
// /private/tmp/agentmux-ownership-acl-sdk265-canonical-repaired. Its omitted
// extended-security bit was refused, never accepted as ACL absence.
// This libc property query is independent of the production mount predicate.
func ownershipEmptyACL(t *testing.T, file *os.File) {
	t.Helper()
	absent, err := darwinownershipfixture.ACLAbsent(file)
	if err != nil {
		t.Fatal("ownership fixture explicit native ACL property query failed")
	}
	if !absent {
		t.Fatal("ownership fixture native ACL property is present")
	}
	t.Log("native_acl_property query=fstatx_np/filesec_query_property present=false")
}

// This fresh ordinary-user control qualifies only the native ACL-property query,
// not an external mount, protected installation, or complete loader.
func TestDarwinOwnershipACLNativeEmptyControl(t *testing.T) {
	if absent, err := darwinownershipfixture.ACLAbsent(nil); err == nil || absent {
		t.Fatal("nil ACL descriptor accepted as explicit absence")
	}
	if goruntime.GOARCH != "arm64" || os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("ordinary-user native ARM64 ACL control required")
	}
	// Resolve only this newly owned temp root: macOS may expose it through
	// /var or /tmp aliases. External manifest paths remain strictly no-follow.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("fresh ACL control canonical temp root unavailable")
	}
	directory := filepath.Join(root, "empty-acl")
	if os.Mkdir(directory, 0700) != nil {
		t.Fatal("fresh ACL control directory unavailable")
	}
	path := filepath.Join(directory, "control")
	created, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("fresh ACL control file unavailable")
	}
	if created.Close() != nil {
		t.Fatal("fresh ACL control creation close failed")
	}
	if absent, err := darwinownershipfixture.ACLAbsent(created); err == nil || absent {
		t.Fatal("already closed ACL descriptor accepted as explicit absence")
	}
	for i, held := range []*os.File{ownershipOpen(t, directory, true), ownershipOpen(t, path, false)} {
		var stat unix.Stat_t
		if unix.Fstat(int(held.Fd()), &stat) != nil || stat.Uid != uint32(os.Getuid()) {
			t.Fatal("fresh ACL control owner differs")
		}
		if i == 0 {
			if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07777 != 0700 {
				t.Fatal("fresh ACL control directory mode differs")
			}
		} else if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Nlink != 1 || stat.Size != 0 {
			t.Fatal("fresh ACL control file differs")
		}
		ownershipEmptyACL(t, held)
	}
}

func TestDarwinOwnershipManifestClosedJSON(t *testing.T) {
	pin := ownershipMountPin{Mountpoint: "/Volumes/disposable", Device: "/dev/disk99s1", VolumeFSID: [2]int32{1, 2}, Dev: 1, RootInode: 2, FileInode: 3, Flags: 1}
	data, err := json.Marshal(ownershipMountManifest{Version: 1, AuthorizedDisposable: true, Owners: pin, NoOwners: pin})
	if err != nil {
		t.Fatal("ownership manifest control unavailable")
	}
	var decoded ownershipMountManifest
	if !ownershipDecode(data, &decoded) {
		t.Fatal("complete exact manifest refused")
	}
	base := string(data)
	for name, invalid := range map[string]string{
		"duplicate":         strings.Replace(base, `"version":1`, `"version":1,"version":1`, 1),
		"escaped-duplicate": strings.Replace(base, `"version":1`, `"version":1,"\u0076ersion":1`, 1),
		"alias":             strings.Replace(base, `"version":`, `"Version":`, 1),
		"missing":           strings.Replace(base, `"version":1,`, "", 1),
		"nested-missing":    strings.Replace(base, `"dev":1,`, "", 1),
		"null":              strings.Replace(base, `"version":1`, `"version":null`, 1),
		"nested-null":       strings.Replace(base, `"volumeFSID":[1,2]`, `"volumeFSID":null`, 1),
		"wrong-type":        strings.Replace(base, `"version":1`, `"version":"1"`, 1),
		"short-array":       strings.Replace(base, `[1,2]`, `[1]`, 1),
		"long-array":        strings.Replace(base, `[1,2]`, `[1,2,3]`, 1),
		"fraction":          strings.Replace(base, `"version":1`, `"version":1.5`, 1),
		"unknown":           strings.Replace(base, `"version":1`, `"extra":0,"version":1`, 1),
		"trailing":          base + "{}",
	} {
		t.Run(name, func(t *testing.T) {
			if invalid == base || ownershipDecode([]byte(invalid), &decoded) {
				t.Fatal("nonclosed ownership manifest accepted")
			}
		})
	}
}

func ownershipManifest(t *testing.T) ownershipMountManifest {
	t.Helper()
	if goruntime.GOARCH != "arm64" || os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getenv("AMX_OWNERSHIP_AUTHORIZED") != "1" {
		t.Fatal("authorized ordinary-user native ARM64 ownership fixture required")
	}
	file := ownershipOpen(t, os.Getenv("AMX_OWNERSHIP_MANIFEST"), false)
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 16384 {
		t.Fatal("ownership fixture manifest is not private and bounded")
	}
	data, err := io.ReadAll(io.LimitReader(file, 16385))
	var after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &after) != nil || after.Dev != stat.Dev || after.Ino != stat.Ino ||
		after.Size != stat.Size || after.Mode != stat.Mode || after.Nlink != stat.Nlink ||
		after.Uid != stat.Uid || after.Mtim != stat.Mtim || after.Ctim != stat.Ctim || int64(len(data)) != stat.Size {
		t.Fatal("ownership fixture manifest changed during read")
	}
	sum := sha256.Sum256(data)
	if err != nil || len(data) > 16384 || hex.EncodeToString(sum[:]) != os.Getenv("AMX_OWNERSHIP_MANIFEST_SHA256") {
		t.Fatal("ownership fixture manifest digest differs")
	}
	var manifest ownershipMountManifest
	if !ownershipDecode(data, &manifest) || manifest.Version != 1 || !manifest.AuthorizedDisposable {
		t.Fatal("ownership fixture manifest contract refused")
	}
	a, b := manifest.Owners, manifest.NoOwners
	if a.Mountpoint == b.Mountpoint || a.Device == b.Device || a.VolumeFSID == b.VolumeFSID || a.Dev == b.Dev {
		t.Fatal("ownership fixture volumes are not distinct")
	}
	if a.Flags^b.Flags != unix.MNT_IGNORE_OWNERSHIP {
		t.Fatal("ownership fixture mount flags differ beyond ownership enforcement")
	}
	return manifest
}

func ownershipDescriptors(t *testing.T, pin ownershipMountPin, ignored bool) []*os.File {
	t.Helper()
	if !strings.HasPrefix(pin.Device, "/dev/disk") || pin.VolumeFSID == [2]int32{} || pin.RootInode == 0 || pin.FileInode == 0 {
		t.Fatal("ownership fixture identity pins missing")
	}
	dir := ownershipOpen(t, pin.Mountpoint, true)
	file := ownershipOpen(t, filepath.Join(pin.Mountpoint, "control"), false)
	files := []*os.File{dir, file}
	ownershipValidate(t, pin, ignored, files)
	return files
}

func ownershipValidate(t *testing.T, pin ownershipMountPin, ignored bool, files []*os.File) {
	t.Helper()
	for i, held := range files {
		ownershipEmptyACL(t, held)
		var mount unix.Statfs_t
		var stat unix.Stat_t
		if unix.Fstatfs(int(held.Fd()), &mount) != nil || unix.Fstat(int(held.Fd()), &stat) != nil {
			t.Fatal("ownership fixture held metadata unavailable")
		}
		if mount.Owner != 0 || mount.Flags != pin.Flags || mount.Flags&unix.MNT_LOCAL == 0 ||
			(mount.Flags&unix.MNT_IGNORE_OWNERSHIP != 0) != ignored ||
			strings.TrimRight(string(mount.Fstypename[:]), "\x00") != "apfs" ||
			strings.TrimRight(string(mount.Mntonname[:]), "\x00") != pin.Mountpoint ||
			strings.TrimRight(string(mount.Mntfromname[:]), "\x00") != pin.Device ||
			mount.Fsid.Val != pin.VolumeFSID || stat.Dev != pin.Dev || stat.Uid != uint32(os.Getuid()) || stat.Flags != 0 {
			t.Fatal("ownership fixture actual mount or object identity differs")
		}
		if i == 0 {
			if stat.Ino != pin.RootInode || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07777 != 0700 {
				t.Fatal("ownership fixture directory differs")
			}
		} else if stat.Ino != pin.FileInode || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Nlink != 1 || stat.Size != 0 {
			t.Fatal("ownership fixture regular file differs")
		}
	}
}

func TestDarwinOwnershipMountRuntimeDescriptorControls(t *testing.T) {
	manifest := ownershipManifest(t)
	for _, control := range []struct {
		name    string
		pin     ownershipMountPin
		ignored bool
	}{
		{"owners", manifest.Owners, false}, {"noowners", manifest.NoOwners, true},
	} {
		t.Run(control.name, func(t *testing.T) {
			files := ownershipDescriptors(t, control.pin, control.ignored)
			for _, held := range files {
				if darwinDescriptorPolicy(int(held.Fd())) == control.ignored {
					t.Fatal("actual runtime mount policy did not match ownership control")
				}
			}
			ownershipValidate(t, control.pin, control.ignored, files)
		})
	}
}

// This read-only control uses the already prepared root; it never provisions,
// chmods, lists, detaches or removes a fixture. Caller UID is not descriptor UID.
func TestDarwinOwnershipSearchOnlyAncestorControl(t *testing.T) {
	if goruntime.GOARCH != "arm64" || os.Getuid() != 501 || os.Geteuid() != 501 ||
		os.Getenv("AMX_OWNERSHIP_AUTHORIZED") != "1" {
		t.Fatal("authorized ordinary UID501 ARM64 search control required")
	}
	const root = "/private/tmp/agentmux-c05-apfs-20261015-7c4e92b1"
	// Bind this observation to the exact prepared root, not another 0711 path.
	const rootInode = 2457222
	// Inspect the 0711 root explicitly; normal walker leaves stay readable.
	rootFD, err := unix.Open(root,
		darwinDirectorySearchOnly|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("prepared ancestor search-only metadata open failed")
	}
	file := os.NewFile(uintptr(rootFD), "prepared-search-only-ancestor")
	t.Cleanup(func() {
		if file.Close() != nil {
			t.Error("prepared ancestor search descriptor close failed")
		}
	})
	// Both walks cross the 0711 root as an intermediate search-only ancestor.
	// Their final mount/control leaves retain the original O_RDONLY access.
	for _, leaf := range []struct {
		path      string
		directory bool
	}{
		{root + "/owners", true}, {root + "/owners/control", false},
	} {
		heldLeaf := ownershipOpen(t, leaf.path, leaf.directory)
		access, err := unix.FcntlInt(heldLeaf.Fd(), unix.F_GETFL, 0)
		if err != nil || access&unix.O_ACCMODE != unix.O_RDONLY ||
			access&(darwinDirectorySearchOnly&^unix.O_DIRECTORY) != 0 {
			t.Fatal("ownership walker leaf no longer has ordinary read-only access")
		}
	}
	var held, named unix.Stat_t
	if unix.Fstat(int(file.Fd()), &held) != nil || unix.Lstat(root, &named) != nil ||
		held.Ino != rootInode || held.Dev != named.Dev || held.Ino != named.Ino ||
		held.Mode != named.Mode || held.Uid != named.Uid || held.Gid != named.Gid ||
		held.Flags != named.Flags || held.Mode&unix.S_IFMT != unix.S_IFDIR ||
		held.Mode&07777 != 0711 || held.Uid != 0 || held.Flags != 0 {
		t.Fatal("prepared search-only ancestor identity or policy differs")
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Owner != 0 ||
		fs.Flags&unix.MNT_LOCAL == 0 || fs.Flags&unix.MNT_IGNORE_OWNERSHIP != 0 ||
		fs.Fsid.Val == [2]int32{} || strings.TrimRight(string(fs.Fstypename[:]), "\x00") != "apfs" {
		t.Fatal("prepared search-only ancestor filesystem differs")
	}
	ownershipEmptyACL(t, file)
	fdflags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || fdflags&unix.FD_CLOEXEC == 0 {
		t.Fatal("search-only descriptor close-on-exec missing")
	}
	// The same root must remain unreadable to this caller; never grant read access.
	readFD, readErr := unix.Open(root,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if readErr == nil {
		if unix.Close(readFD) != nil {
			t.Error("unexpected read descriptor close failed")
		}
		t.Fatal("prepared ancestor unexpectedly permits directory reads")
	}
	if readErr != unix.EACCES {
		t.Fatal("prepared ancestor read refusal differs from EACCES")
	}
	var after unix.Stat_t
	var afterFS unix.Statfs_t
	if unix.Fstat(int(file.Fd()), &after) != nil || unix.Fstatfs(int(file.Fd()), &afterFS) != nil ||
		after.Dev != held.Dev || after.Ino != held.Ino || after.Mode != held.Mode ||
		after.Uid != held.Uid || after.Gid != held.Gid || after.Flags != held.Flags ||
		afterFS.Fsid != fs.Fsid || afterFS.Flags != fs.Flags || afterFS.Owner != fs.Owner ||
		afterFS.Mntonname != fs.Mntonname || afterFS.Mntfromname != fs.Mntfromname {
		t.Fatal("prepared ancestor changed during search control")
	}
	ownershipEmptyACL(t, file)
	t.Log("caller_uid=501 descriptor_uid=0 search_metadata=true readonly_refused=true")
}
