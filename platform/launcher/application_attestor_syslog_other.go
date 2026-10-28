//go:build (linux || darwin) && !(darwin && cgo)

package launcher

func writeSystemLog(string) {}
