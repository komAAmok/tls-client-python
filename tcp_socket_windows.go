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

// setWindowScale sets the TCP window scale factor.
// On Windows, the window scale is derived from the receive buffer size and the
// TCP1323Opts registry setting. We accept the value silently.
func setWindowScale(fd int, scale int) error {
	if scale < 0 || scale > 14 {
		return fmt.Errorf("window scale %d out of range (0-14)", scale)
	}
	return nil
}
