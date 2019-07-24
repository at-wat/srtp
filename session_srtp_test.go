package srtp

import (
	"net"
	"runtime"
	"testing"
)

func TestSessionSRTPLeak(t *testing.T) {
	_, cli := net.Pipe()
	finalized := false
	func() {
		sess, err := NewSessionSRTP(cli, &Config{
			Keys: SessionKeys{
				make([]byte, 16),
				make([]byte, 14),
				make([]byte, 16),
				make([]byte, 14),
			},
			Profile: ProtectionProfileAes128CmHmacSha1_80,
		})
		if err != nil {
			t.Fatalf("Failed to create SessionSRTP: %v", err)
		}
		runtime.SetFinalizer(sess, func(*SessionSRTP) {
			finalized = true
		})
		sess.Close()
	}()

	// sess is now Closed and unreferenced; It must be finalized by GC.
	runtime.GC()
	if !finalized {
		t.Error("SessionSRTP is expected to be finalized after unreferenced, but not be finalized.")
	}
}
