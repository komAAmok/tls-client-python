//go:build windows

package tls_client

import (
	"fmt"
	"syscall"
	"unsafe"
)

// setTTL sets the IP TTL (Time To Live) on the socket.
// On Windows, IP_TTL is supported.
func setTTL(fd int, ttl int) error {
	if ttl <= 0 || ttl > 255 {
		return fmt.Errorf("ttl value %d out of range (1-255)", ttl)
	}
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}

// setMSS sets TCP Maximum Segment Size on the socket.
// On Windows, TCP_MAXSEG = 0x2 (same as Unix).
func setMSS(fd int, mss int) error {
	if mss <= 0 {
		return fmt.Errorf("mss value %d out of range", mss)
	}
	const tcpMaxSeg = 0x2
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, tcpMaxSeg, mss)
}

// setWindowSize sets the TCP receive window size via SO_RCVBUF.
func setWindowSize(fd int, windowSize int) error {
	if windowSize <= 0 {
		return fmt.Errorf("window size %d out of range", windowSize)
	}
	// On Windows, SO_RCVBUF expects the value as a byte buffer
	buf := int32(windowSize)
	return syscall.Setsockopt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, (*byte)(unsafe.Pointer(&buf)), 4)
}

// setWindowScale validates the TCP window scale factor.
//
// On Windows the scale is derived from the receive buffer size plus the
// TCP1323Opts registry setting, so it cannot be set per-socket.  The value is
// applied indirectly through setWindowSize; this function only range-checks
// the hint so an invalid one still reaches the caller as an error.
func setWindowScale(fd int, scale int) error {
	_ = fd
	if scale < 0 || scale > 14 {
		return fmt.Errorf("window scale %d out of range (0-14)", scale)
	}
	return nil
}

// setWindowClamp is a no-op on Windows: TCP_WINDOW_CLAMP is Linux-only.
func setWindowClamp(fd int, clamp int) error {
	if clamp <= 0 {
		return fmt.Errorf("window clamp %d out of range", clamp)
	}
	return nil
}

// setTOS sets the IPv4 Type-Of-Service / DSCP byte.
func setTOS(fd int, tos int) error {
	if tos < 0 || tos > 255 {
		return fmt.Errorf("tos %d out of range (0-255)", tos)
	}
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tos)
}

// setDontFragment toggles the IP Don't-Fragment bit.
// Windows exposes IP_DONTFRAGMENT = 14 on IPPROTO_IP.
func setDontFragment(fd int, on bool) error {
	const ipDontFragment = 14
	v := 0
	if on {
		v = 1
	}
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipDontFragment, v)
}

// setNoDelay disables Nagle's algorithm (TCP_NODELAY).
func setNoDelay(fd int, on bool) error {
	v := 0
	if on {
		v = 1
	}
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, v)
}
