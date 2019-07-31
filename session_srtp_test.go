package srtp

import (
	"net"
	"runtime"
	"testing"
	"time"
)

func TestSessionSRTPLeak(t *testing.T) {
	_, cli := net.Pipe()

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

	finalized := make(chan struct{})
	runtime.SetFinalizer(sess, func(interface{}) {
		close(finalized)
	})
	defer func() {
		// sess is Closed and unreferenced. It must be finalized by GC.
		runtime.GC()
		select {
		case <-finalized:
		case <-time.After(time.Second):
			t.Error("SessionSRTP is not finalized.")
		}
	}()

	sess.Close()
}
