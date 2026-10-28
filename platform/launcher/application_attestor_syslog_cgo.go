//go:build darwin && cgo

package launcher

/*
#include <stdlib.h>
#include <syslog.h>
static void agentmux_syslog(const char *record) { syslog(LOG_ERR | LOG_USER, "%s", record); }
*/
import "C"

import "unsafe"

// writeSystemLog uses syslog(3), which macOS keeps in the unified log. Go's
// log/syslog writes to a socket that macOS does not keep.
func writeSystemLog(record string) {
	text := C.CString(record)
	defer C.free(unsafe.Pointer(text))
	C.agentmux_syslog(text)
}
