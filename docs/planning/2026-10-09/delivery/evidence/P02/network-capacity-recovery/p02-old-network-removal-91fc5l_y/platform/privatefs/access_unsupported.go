//go:build !linux && !darwin

package privatefs

func checkNativeDescriptor(uintptr, AccessKind) error { return ErrPlatformUnqualified }
