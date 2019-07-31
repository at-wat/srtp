package srtp

import (
	"net"
	"runtime"
	"testing"
	"time"
)

func TestSessionSRTCPLeak(t *testing.T) {
	_, cli := net.Pipe()

	sess, err := NewSessionSRTCP(cli, &Config{
		Keys: SessionKeys{
			make([]byte, 16),
			make([]byte, 14),
			make([]byte, 16),
			make([]byte, 14),
		},
		Profile: ProtectionProfileAes128CmHmacSha1_80,
	})
	if err != nil {
		t.Fatalf("Failed to create SessionSRTCP: %v", err)
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
			t.Error("SessionSRTCP is not finalized.")
		}
	}()

	sess.Close()
}
