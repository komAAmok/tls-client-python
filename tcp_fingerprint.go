package tls_client

import (
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/bogdanfinn/tls-client/profiles"
)

// MergeTcpFingerprint merges a user-provided override into the automatic TCP fingerprint.
// Non-nil fields in the override replace the corresponding automatic field.
// Returns nil if both are nil.
func MergeTcpFingerprint(auto, override *profiles.TcpFingerprint) *profiles.TcpFingerprint {
	if auto == nil && override == nil {
		return nil
	}
	if override == nil {
		out := *auto
		return &out
	}
	if auto == nil {
		out := *override
		return &out
	}
	out := *auto
	if override.TTL != nil {
		out.TTL = intPtrCopy(override.TTL)
	}
	if override.WindowSize != nil {
		out.WindowSize = intPtrCopy(override.WindowSize)
	}
	if override.WindowScale != nil {
		out.WindowScale = intPtrCopy(override.WindowScale)
	}
	if override.MSS != nil {
		out.MSS = intPtrCopy(override.MSS)
	}
	if override.DontFragment != nil {
		out.DontFragment = boolPtrCopy(override.DontFragment)
	}
	if override.TOS != nil {
		out.TOS = intPtrCopy(override.TOS)
	}
	if override.NoDelay != nil {
		out.NoDelay = boolPtrCopy(override.NoDelay)
	}
	if override.WindowClamp != nil {
		out.WindowClamp = intPtrCopy(override.WindowClamp)
	}
	if override.IPIDMode != "" {
		out.IPIDMode = override.IPIDMode
	}
	return &out
}

func intPtrCopy(v *int) *int {
	c := *v
	return &c
}

func boolPtrCopy(v *bool) *bool {
	c := *v
	return &c
}

// tcpControl returns a net.Dialer.Control function that applies TCP/IP fingerprint
// parameters to the socket after creation but before the connection is established.
// Unsupported options on the current OS are silently skipped.
func tcpControl(fp *profiles.TcpFingerprint) func(string, string, syscall.RawConn) error {
	if fp == nil {
		return nil
	}
	return func(network string, address string, c syscall.RawConn) error {
		if !strings.HasPrefix(network, "tcp") {
			return nil
		}

		var ctrlErr error
		err := c.Control(func(fd uintptr) {
			ctrlErr = applySocketOptions(int(fd), fp)
		})
		if err != nil {
			return err
		}
		return ctrlErr
	}
}

// applySocketOptions applies the TCP fingerprint parameters to the given socket fd.
// Errors from unsupported options are silently ignored (the fingerprint is best-effort).
func applySocketOptions(fd int, fp *profiles.TcpFingerprint) error {
	var errs []error

	if fp.TTL != nil {
		if err := setTTL(fd, *fp.TTL); err != nil {
			errs = append(errs, fmt.Errorf("TTL(%d): %w", *fp.TTL, err))
		}
	}
	if fp.MSS != nil {
		if err := setMSS(fd, *fp.MSS); err != nil {
			errs = append(errs, fmt.Errorf("MSS(%d): %w", *fp.MSS, err))
		}
	}
	if fp.WindowSize != nil {
		if err := setWindowSize(fd, *fp.WindowSize); err != nil {
			errs = append(errs, fmt.Errorf("WindowSize(%d): %w", *fp.WindowSize, err))
		}
	}
	if fp.WindowScale != nil {
		if err := setWindowScale(fd, *fp.WindowScale); err != nil {
			errs = append(errs, fmt.Errorf("WindowScale(%d): %w", *fp.WindowScale, err))
		}
	}
	if fp.WindowClamp != nil {
		if err := setWindowClamp(fd, *fp.WindowClamp); err != nil {
			errs = append(errs, fmt.Errorf("WindowClamp(%d): %w", *fp.WindowClamp, err))
		}
	}
	if fp.TOS != nil {
		if err := setTOS(fd, *fp.TOS); err != nil {
			errs = append(errs, fmt.Errorf("TOS(%d): %w", *fp.TOS, err))
		}
	}
	if fp.DontFragment != nil {
		if err := setDontFragment(fd, *fp.DontFragment); err != nil {
			errs = append(errs, fmt.Errorf("DontFragment(%t): %w", *fp.DontFragment, err))
		}
	}
	if fp.NoDelay != nil {
		if err := setNoDelay(fd, *fp.NoDelay); err != nil {
			errs = append(errs, fmt.Errorf("NoDelay(%t): %w", *fp.NoDelay, err))
		}
	}

	return errors.Join(errs...)
}
