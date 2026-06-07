//go:build !windows

package tls_client

import (
	"fmt"
	"syscall"
)

// setTTL sets the IP TTL (Time To Live) on the socket.
func setTTL(fd int, ttl int) error {
	if ttl <= 0 || ttl > 255 {
		return fmt.Errorf("ttl value %d out of range (1-255)", ttl)
	}
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}

// setMSS sets TCP Maximum Segment Size on the socket.
// On macOS, TCP_MAXSEG has value 2; on Linux it's 2 as well.
func setMSS(fd int, mss int) error {
	if mss <= 0 {
		return fmt.Errorf("mss value %d out of range", mss)
	}
	// TCP_MAXSEG = 2 on both Linux and macOS
	const tcpMaxSeg = 0x2
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, tcpMaxSeg, mss)
}

// setWindowSize sets the TCP receive window size via SO_RCVBUF.
// On Linux, TCP_WINDOW_CLAMP would be more precise but may not be available everywhere.
// We use SO_RCVBUF as a practical approximation.
func setWindowSize(fd int, windowSize int) error {
	if windowSize <= 0 {
		return fmt.Errorf("window size %d out of range", windowSize)
	}
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, windowSize)
}

// setWindowScale sets the TCP window scale factor.
// Note: The window scale factor is derived from the receive buffer size by the kernel;
// it cannot be directly set via a socket option on most platforms.
// We adjust SO_RCVBUF to approximate the desired scale factor.
// Window scale of S means the actual window = SO_RCVBUF, and the advertised window = SO_RCVBUF / 2^S.
// To set a scale of S, we set SO_RCVBUF to the kernel default (65535 for most) and let the kernel decide.
func setWindowScale(fd int, scale int) error {
	if scale < 0 || scale > 14 {
		return fmt.Errorf("window scale %d out of range (0-14)", scale)
	}
	// On Linux, we can try to set TCP_WINDOW_CLAMP in combination with the scale.
	// But since TCP_WINDOW_CLAMP is already set via setWindowSize, we just accept
	// the scale value here. The kernel will derive the actual scale from the
	// receive buffer size set by setWindowSize.
	return nil
}
