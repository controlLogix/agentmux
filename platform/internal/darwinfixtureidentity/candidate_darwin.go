//go:build darwin && cgo && agentmux_bootstrap_docker && agentmux_darwin_identity_candidate

package darwinfixtureidentity

import (
	"errors"
	"runtime"

	"golang.org/x/sys/unix"
)

// candidateEvidence is diagnostic evidence, never an enrolled process proof.
type candidateEvidence struct {
	architecture, productVersion, kernelRelease string
	compilerSDK                                 int64
	layout                                      nativeLayoutEvidence
}

// candidateProbeAdmission permits only the reviewed diagnostic tuple. It does
// not change nativeAdmission, NewCreator or any process-control constructor.
func candidateProbeAdmission() (candidateEvidence, error) {
	var evidence candidateEvidence
	if runtime.GOARCH != "arm64" {
		return evidence, errors.New("candidate_architecture_refused")
	}
	version, sdk, err := nativeProbeAdmission()
	if err != nil {
		return evidence, errors.New("candidate_native_admission_refused")
	}
	release, err := unix.Sysctl("kern.osrelease")
	if err != nil || version != "26.6" || release != "25.6.0" || sdk != 270000 {
		return evidence, errors.New("candidate_exact_tuple_refused")
	}
	evidence = candidateEvidence{architecture: runtime.GOARCH, productVersion: version,
		kernelRelease: release, compilerSDK: sdk, layout: nativeSelfLayout()}
	layout := evidence.layout
	if layout.uniqueSize != 56 || layout.versionOffset != 32 ||
		layout.uniqueOffset != layout.bsdSize || layout.combinedSize != layout.bsdSize+layout.uniqueSize ||
		layout.selector != 18 || layout.returnedSize <= 0 ||
		uint64(layout.returnedSize) != layout.combinedSize || !layout.identityValid {
		return evidence, errors.New("candidate_own_identity_layout_refused")
	}
	return evidence, nil
}

// This constructor exists only in the separately tagged internal diagnostic.
// Normal NewCreator continues to use normalAdmission and refuses SDK 27.
type candidateAdmission struct{}

func (candidateAdmission) check() error      { _, err := candidateProbeAdmission(); return err }
func newCandidateCreator() (*Creator, error) { return newCreator(candidateAdmission{}) }
