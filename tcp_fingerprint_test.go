package tls_client

import (
	"testing"

	"github.com/bogdanfinn/tls-client/profiles"
)

func TestMergeTcpFingerprintNilBoth(t *testing.T) {
	if got := MergeTcpFingerprint(nil, nil); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestMergeTcpFingerprintOverrideWins(t *testing.T) {
	auto := &profiles.TcpFingerprint{TTL: profiles.IntPtr(64), MSS: profiles.IntPtr(1460)}
	override := &profiles.TcpFingerprint{TTL: profiles.IntPtr(128)}

	got := MergeTcpFingerprint(auto, override)
	if got.TTL == nil || *got.TTL != 128 {
		t.Fatalf("override TTL not applied: %+v", got.TTL)
	}
	if got.MSS == nil || *got.MSS != 1460 {
		t.Fatalf("automatic MSS should survive a partial override: %+v", got.MSS)
	}
}

func TestMergeTcpFingerprintDoesNotAliasInputs(t *testing.T) {
	auto := &profiles.TcpFingerprint{TTL: profiles.IntPtr(64)}
	override := &profiles.TcpFingerprint{TTL: profiles.IntPtr(128)}

	got := MergeTcpFingerprint(auto, override)
	*got.TTL = 7

	if *auto.TTL != 64 || *override.TTL != 128 {
		t.Fatal("merge aliased a caller-owned pointer")
	}
}

func TestMergeTcpFingerprintDeepFields(t *testing.T) {
	auto := &profiles.TcpFingerprint{
		DontFragment: profiles.BoolPtr(true),
		NoDelay:      profiles.BoolPtr(true),
		IPIDMode:     "random",
		WindowClamp:  profiles.IntPtr(65535),
	}
	override := &profiles.TcpFingerprint{
		DontFragment: profiles.BoolPtr(false),
		TOS:          profiles.IntPtr(8),
	}

	got := MergeTcpFingerprint(auto, override)

	if got.DontFragment == nil || *got.DontFragment {
		t.Fatal("override DontFragment not applied")
	}
	if got.TOS == nil || *got.TOS != 8 {
		t.Fatal("override TOS not applied")
	}
	if got.NoDelay == nil || !*got.NoDelay {
		t.Fatal("automatic NoDelay should survive")
	}
	if got.IPIDMode != "random" {
		t.Fatalf("automatic IPIDMode should survive, got %q", got.IPIDMode)
	}
	if got.WindowClamp == nil || *got.WindowClamp != 65535 {
		t.Fatal("automatic WindowClamp should survive")
	}
}

func TestDefaultTcpFingerprintsAreOSCoherent(t *testing.T) {
	win, ok := profiles.DefaultTcpFingerprints["Windows"]
	if !ok {
		t.Fatal("Windows default missing")
	}
	if *win.TTL != 128 {
		t.Fatalf("Windows TTL should be 128, got %d", *win.TTL)
	}
	// Windows only sets DF for PMTU-discovered routes, so the default is off.
	if win.DontFragment == nil || *win.DontFragment {
		t.Fatal("Windows default should leave DF clear")
	}

	linux := profiles.DefaultTcpFingerprints["Linux"]
	if *linux.TTL != 64 {
		t.Fatalf("Linux TTL should be 64, got %d", *linux.TTL)
	}
	if linux.DontFragment == nil || !*linux.DontFragment {
		t.Fatal("Linux sets DF on every TCP segment")
	}
}

func TestApplySocketOptionsRejectsOutOfRange(t *testing.T) {
	// fd -1 is never a valid socket, so every setsockopt fails; the point is
	// that the range checks fire before the syscall and errors are collected.
	fp := &profiles.TcpFingerprint{
		TTL: profiles.IntPtr(9999),
		TOS: profiles.IntPtr(9999),
	}
	err := applySocketOptions(-1, fp)
	if err == nil {
		t.Fatal("out-of-range TTL/TOS should produce an error")
	}
}
