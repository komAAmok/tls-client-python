//go:build !windows

package tls_client

import (
	"fmt"
	"runtime"
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
	// Darwin rejects TCP_MAXSEG from net.Dialer.Control because the socket is
	// not connected yet (EINVAL). The kernel derives the effective MSS from
	// the route MTU during connect, so this option is best-effort on macOS.
	// Returning nil here prevents an optional fingerprint hint from aborting
	// the entire request.
	if runtime.GOOS == "darwin" {
		return nil
	}
	// TCP_MAXSEG = 2 on supported non-Darwin Unix systems.
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

// setWindowScale validates the TCP window scale factor.
//
// The scale factor is NOT settable through a socket option: the kernel
// derives it from the receive buffer size at connect time and advertises it
// in the SYN.  The value is therefore applied indirectly — WindowSize drives
// SO_RCVBUF and the resulting scale follows from it — so this function only
// range-checks the hint and reports an invalid one to the caller.
func setWindowScale(fd int, scale int) error {
	_ = fd
	if scale < 0 || scale > 14 {
		return fmt.Errorf("window scale %d out of range (0-14)", scale)
	}
	return nil
}

// setWindowClamp caps the advertised receive window.  Linux implements this as
// TCP_WINDOW_CLAMP; other Unix systems ignore the value.
func setWindowClamp(fd int, clamp int) error {
	if clamp <= 0 {
		return fmt.Errorf("window clamp %d out of range", clamp)
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	// TCP_WINDOW_CLAMP = 10 on Linux.
	const tcpWindowClamp = 0xa
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, tcpWindowClamp, clamp)
}

// setTOS sets the IPv4 Type-Of-Service / DSCP byte.
func setTOS(fd int, tos int) error {
	if tos < 0 || tos > 255 {
		return fmt.Errorf("tos %d out of range (0-255)", tos)
	}
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, tos)
}

// setDontFragment toggles PMTU discovery, which drives the IP Don't-Fragment
// bit.  Linux uses IP_MTU_DISCOVER with IP_PMTUDISC_DO; Darwin has no
// equivalent pre-connect option and relies on the route's default.
func setDontFragment(fd int, on bool) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	const ipMtuDiscover = 0xa
	const ipPmtudiscDo = 2
	const ipPmtudiscDont = 0
	v := ipPmtudiscDont
	if on {
		v = ipPmtudiscDo
	}
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, ipMtuDiscover, v)
}

// setNoDelay disables Nagle's algorithm (TCP_NODELAY).
func setNoDelay(fd int, on bool) error {
	v := 0
	if on {
		v = 1
	}
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, v)
}
