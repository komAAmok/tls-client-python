//go:build profile

package main

/*
#include <stdlib.h>
*/

import "C"

// Runtime introspection, compiled only with -tags profile.
//
// It lives behind a build tag because it is not free: runtime/pprof and
// runtime/debug add ~230 KB to the shared library (14,070,664 -> 14,300,744
// on linux/amd64).  A release artifact should not carry a debugging surface
// nobody calls at runtime, but every leak investigation in this project needs
// it, so it stays one flag away:
//
//   python cffi_binding/build_binding.py --lib --tags profile,netgo,osusergo
//
// The Python helpers in tls_client/_core.py (runtime_stats, dump_goroutines,
// set_go_gc_percent, set_go_memory_limit, force_go_gc) raise a clear error when
// the loaded library was built without it, so a test that needs introspection
// says so instead of silently reading zeros.

import (
	"bytes"
	"os"
	"runtime"
	"runtime/debug"
	runtime_pprof "runtime/pprof"
)

// Out-parameters only: the CDEF is derived from these signatures, and a
// multi-value return of C types has no single C spelling to derive.
// Any pointer may be nil to skip that field.
//
//export GetRuntimeStats
func GetRuntimeStats(goroutines *C.int, heapObjects *C.longlong, heapInuse *C.longlong, heapAlloc *C.longlong, numGC *C.int) C.int {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	if goroutines != nil {
		*goroutines = C.int(runtime.NumGoroutine())
	}
	if heapObjects != nil {
		*heapObjects = C.longlong(ms.HeapObjects)
	}
	if heapInuse != nil {
		*heapInuse = C.longlong(ms.HeapInuse)
	}
	if heapAlloc != nil {
		*heapAlloc = C.longlong(ms.HeapAlloc)
	}
	if numGC != nil {
		*numGC = C.int(ms.NumGC)
	}
	return 0
}

// Writes the goroutine profile (debug=1, aggregated by stack) to path and
// returns the number of bytes written, or -1 on failure.
//
//export DumpGoroutineProfile
func DumpGoroutineProfile(path *C.char) C.int {
	if path == nil {
		return -1
	}
	var buf bytes.Buffer
	// debug = 1 aggregates equal stacks, which is what a leak diff wants.
	// WriteTo returns only an error in that mode, so the size comes from the
	// buffer itself.
	if err := runtime_pprof.Lookup("goroutine").WriteTo(&buf, 1); err != nil {
		return -1
	}
	if err := os.WriteFile(C.GoString(path), buf.Bytes(), 0o644); err != nil {
		return -1
	}
	return C.int(buf.Len())
}

// Adjusts GOGC at runtime. 0 disables GC; <0 restores the default.
//
//export SetGCPercent
func SetGCPercent(percent C.int) C.int {
	return C.int(debug.SetGCPercent(int(percent)))
}

// Sets the Go soft memory limit in bytes. <0 removes the limit.
//
//export SetMemoryLimit
func SetMemoryLimit(limit C.longlong) C.longlong {
	return C.longlong(debug.SetMemoryLimit(int64(limit)))
}

//export ForceGC
func ForceGC() {
	runtime.GC()
}

