//go:build darwin && cgo && agentmux_darwin_ownership_mount

// This standalone inspector is unprivileged. Never execute it from root setup.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/controlLogix/agentmux/platform/internal/darwinownershipfixture"
	"golang.org/x/sys/unix"
)

const fixtureRoot = "/private/tmp/agentmux-c05-apfs-20261015-7c4e92b1"
const outputRoot = "/private/tmp/agentmux-c05-inspector-20261015-7c4e92b1"

// Fixture-only Darwin O_SEARCH: SDK26.5 sys/fcntl.h lines162-163 defines
// O_EXEC=0x40000000 and O_SEARCH=(O_EXEC|O_DIRECTORY). x/sys v0.48.0 omits both.
// Search is for ancestors; final directory/file leaves keep read access.
const darwinDirectorySearchOnly = 0x40000000 | unix.O_DIRECTORY

type mountPin struct {
	Mountpoint string   `json:"mountpoint"`
	Device     string   `json:"device"`
	VolumeFSID [2]int32 `json:"volumeFSID"`
	Dev        int32    `json:"dev"`
	RootInode  uint64   `json:"rootInode"`
	FileInode  uint64   `json:"fileInode"`
	Flags      uint32   `json:"flags"`
}
type manifest struct {
	Version              int      `json:"version"`
	AuthorizedDisposable bool     `json:"authorizedDisposable"`
	Owners               mountPin `json:"owners"`
	NoOwners             mountPin `json:"noOwners"`
}

func run() (report []byte, failure error) {
	if len(os.Args) != 1 || runtime.GOARCH != "arm64" || os.Getuid() != 501 || os.Geteuid() != 501 {
		return nil, inspectorFailure("inspector_native_uid501_required")
	}
	var held []*os.File
	defer func() {
		for len(held) > 0 {
			last := len(held) - 1
			file := held[last]
			held = held[:last]
			failure = errors.Join(failure, file.Close())
		}
	}()
	keep := func(fd int) *os.File {
		file := os.NewFile(uintptr(fd), "owned-mount-inspector")
		held = append(held, file)
		return file
	}
	open := func(path string, directory bool) (*os.File, error) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return nil, inspectorFailure("inspector_canonical_path_required")
		}
		fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, inspectorFailure("inspector_root_open_failed")
		}
		parent := keep(fd)
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		for i, part := range parts {
			flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
			if i < len(parts)-1 || (directory && path == fixtureRoot) {
				flags |= darwinDirectorySearchOnly
			} else if directory {
				flags |= unix.O_DIRECTORY
			}
			fd, err = unix.Openat(int(parent.Fd()), part, flags, 0)
			if err != nil {
				return nil, inspectorFailure("inspector_nofollow_open_failed")
			}
			parent = keep(fd)
		}
		return parent, nil
	}
	root, err := open(fixtureRoot, true)
	if err != nil {
		return nil, err
	}
	var parentStat unix.Stat_t
	if unix.Fstat(int(root.Fd()), &parentStat) != nil || parentStat.Uid != 0 ||
		parentStat.Mode&07777 != 0711 {
		return nil, inspectorFailure("inspector_root_parent_policy_failed")
	}
	var pins [2]mountPin
	for i, label := range []string{"owners", "noowners"} {
		mountpoint := fixtureRoot + "/" + label
		directory, err := open(mountpoint, true)
		if err != nil {
			return nil, err
		}
		control, err := open(mountpoint+"/control", false)
		if err != nil {
			return nil, err
		}
		var pin mountPin
		for j, file := range []*os.File{directory, control} {
			var fs unix.Statfs_t
			var stat unix.Stat_t
			if unix.Fstatfs(int(file.Fd()), &fs) != nil || unix.Fstat(int(file.Fd()), &stat) != nil {
				return nil, inspectorFailure("inspector_held_metadata_failed")
			}
			device := strings.TrimRight(string(fs.Mntfromname[:]), "\x00")
			if fs.Owner != 0 || fs.Flags&unix.MNT_LOCAL == 0 ||
				(fs.Flags&unix.MNT_IGNORE_OWNERSHIP != 0) != (i == 1) ||
				strings.TrimRight(string(fs.Fstypename[:]), "\x00") != "apfs" ||
				strings.TrimRight(string(fs.Mntonname[:]), "\x00") != mountpoint ||
				!strings.HasPrefix(device, "/dev/disk") || stat.Uid != 501 || stat.Flags != 0 ||
				stat.Dev == parentStat.Dev || fs.Fsid.Val == [2]int32{} {
				return nil, inspectorFailure("inspector_mount_policy_failed")
			}
			absent, err := darwinownershipfixture.ACLAbsent(file)
			if err != nil || !absent {
				return nil, inspectorFailure("inspector_explicit_acl_absence_required")
			}
			if j == 0 {
				if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07777 != 0700 {
					return nil, inspectorFailure("inspector_directory_policy_failed")
				}
				pin = mountPin{Mountpoint: mountpoint, Device: device, VolumeFSID: fs.Fsid.Val,
					Dev: stat.Dev, RootInode: stat.Ino, Flags: fs.Flags}
			} else {
				if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 ||
					stat.Nlink != 1 || stat.Size != 0 || pin.Dev != stat.Dev ||
					pin.Device != device || pin.VolumeFSID != fs.Fsid.Val || pin.Flags != fs.Flags {
					return nil, inspectorFailure("inspector_control_policy_failed")
				}
				pin.FileInode = stat.Ino
			}
		}
		pins[i] = pin
	}
	if pins[0].Dev == pins[1].Dev || pins[0].Device == pins[1].Device ||
		pins[0].VolumeFSID == pins[1].VolumeFSID ||
		pins[0].Flags^pins[1].Flags != unix.MNT_IGNORE_OWNERSHIP {
		return nil, inspectorFailure("inspector_matched_mount_flags_required")
	}
	data, err := json.Marshal(manifest{Version: 1, AuthorizedDisposable: true, Owners: pins[0], NoOwners: pins[1]})
	if err != nil {
		return nil, inspectorFailure("inspector_manifest_encoding_failed")
	}
	if os.Mkdir(outputRoot, 0700) != nil {
		return nil, inspectorFailure("inspector_exclusive_output_directory_failed")
	}
	outdir, err := open(outputRoot, true)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(outdir.Fd()), "manifest.json",
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, inspectorFailure("inspector_exclusive_manifest_failed")
	}
	file := keep(fd)
	if n, err := file.Write(data); err != nil || n != len(data) {
		return nil, inspectorFailure("inspector_manifest_write_failed")
	}
	if file.Sync() != nil {
		return nil, inspectorFailure("inspector_manifest_sync_failed")
	}
	sum := sha256.Sum256(data)
	return json.Marshal(struct {
		Manifest                   string `json:"manifest"`
		SHA256                     string `json:"sha256"`
		RootReceiptBindingRequired bool   `json:"rootReceiptBindingRequired"`
	}{outputRoot + "/manifest.json", hex.EncodeToString(sum[:]), true})
}

// inspectorFailure carries only the closed source stage literals below.
type inspectorFailure string

func (failure inspectorFailure) Error() string { return string(failure) }

// Never print arbitrary error strings, native errno text, or paths.
func inspectorFailureCode(failure error) string {
	var stage inspectorFailure
	if errors.As(failure, &stage) {
		switch stage {
		case "inspector_canonical_path_required",
			"inspector_control_policy_failed",
			"inspector_directory_policy_failed",
			"inspector_exclusive_manifest_failed",
			"inspector_exclusive_output_directory_failed",
			"inspector_explicit_acl_absence_required",
			"inspector_held_metadata_failed",
			"inspector_manifest_encoding_failed",
			"inspector_manifest_sync_failed",
			"inspector_manifest_write_failed",
			"inspector_matched_mount_flags_required",
			"inspector_mount_policy_failed",
			"inspector_native_uid501_required",
			"inspector_nofollow_open_failed",
			"inspector_root_open_failed",
			"inspector_root_parent_policy_failed":
			return string(stage)
		}
	}
	return "inspector_unclassified_cleanup_failure"
}

func main() {
	report, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "inspector_refused_resources_retained")
		fmt.Fprintln(os.Stderr, inspectorFailureCode(err))
		os.Exit(1)
	}
	fmt.Println(string(report))
}
