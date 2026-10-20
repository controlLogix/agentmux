package plugins

import (
	"fmt"
	"io"
)

// AdmissionCleanupFailure retains the exact regular-file/root owner and its
// completed Close failure. Repeating Close cannot prove that historical failure
// succeeded, so this error is not converted into success by a second close.
type AdmissionCleanupFailure struct {
	owner     io.Closer
	operation error
	cause     error
}

func (*AdmissionCleanupFailure) Error() string    { return "package_admission_cleanup_incomplete" }
func (*AdmissionCleanupFailure) Code() string     { return "package_admission_cleanup_incomplete" }
func (*AdmissionCleanupFailure) String() string   { return "package_admission_cleanup_incomplete" }
func (*AdmissionCleanupFailure) GoString() string { return "package_admission_cleanup_incomplete" }
func (*AdmissionCleanupFailure) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "package_admission_cleanup_incomplete")
}
func (*AdmissionCleanupFailure) MarshalJSON() ([]byte, error) {
	return []byte(`{"code":"package_admission_cleanup_incomplete"}`), nil
}
func (e *AdmissionCleanupFailure) Unwrap() []error {
	if e.operation == nil {
		return []error{e.cause}
	}
	return []error{e.operation, e.cause}
}
func closeAdmission(owner io.Closer, operation error) error {
	if err := owner.Close(); err != nil {
		return &AdmissionCleanupFailure{owner: owner, operation: operation, cause: err}
	}
	return operation
}
