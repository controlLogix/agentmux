//go:build darwin && !cgo

package privatefs

func checkNativeDescriptor(uintptr, AccessKind) error { return ErrPlatformUnqualified }
