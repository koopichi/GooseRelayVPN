package carrier

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kianmhz/relay-tunnel/internal/frame"
)

const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// echoServer decodes the incoming batch, echoes each frame's payload back
// (with the SYN bit cleared and seq reset per session), and returns it.
func echoServer(t *testing.T, aead *frame.Crypto) (*httptest.Server, *int) {
	t.Helper()
	var hits int
	var mu sync.Mutex
	rxSeqBySession := map[[frame.SessionIDLen]byte]uint64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		in, err := frame.DecodeBatch(aead, body)
		if err != nil {
			t.Errorf("server decode: %v", err)
			w.WriteHeader(500)
			return
		}
		var out []*frame.Frame
		mu.Lock()
		for _, f := range in {
			seq := rxSeqBySession[f.SessionID]
			rxSeqBySession[f.SessionID] = seq + 1
			out = append(out, &frame.Frame{
				SessionID: f.SessionID,
				Seq:       seq,
				Payload:   f.Payload,
			})
		}
		mu.Unlock()
		respBody, _ := frame.EncodeBatch(aead, out)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(respBody)
	}))
	return srv, &hits
}

func TestCarrier_RoundTripEcho(t *testing.T) {
	aead, err := frame.NewCryptoFromHexKey(testKeyHex)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	srv, _ := echoServer(t, aead)
	defer srv.Close()

	c, err := New(Config{
		ScriptURL: srv.URL,
		AESKeyHex: testKeyHex,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(done)
	}()

	s := c.NewSession("example.com:80")
	s.EnqueueTx([]byte("hello"))

	// Read the echoed payload from the session's RxChan.
	select {
	case got := <-s.RxChan:
		if string(got) != "hello" {
			t.Fatalf("got %q want %q", got, "hello")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for echoed payload")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}
}

func TestCarrier_UnknownSessionFramesDropped(t *testing.T) {
	aead, _ := frame.NewCryptoFromHexKey(testKeyHex)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always reply with one frame for an unknown session ID.
		var unknown [frame.SessionIDLen]byte
		for i := range unknown {
			unknown[i] = 0xEE
		}
		body, _ := frame.EncodeBatch(aead, []*frame.Frame{
			{SessionID: unknown, Seq: 0, Payload: []byte("ghost")},
		})
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	c, err := New(Config{ScriptURL: srv.URL, AESKeyHex: testKeyHex})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	// Just let it run a couple of poll cycles. A panic / data race here is
	// the failure mode; the assertion is "doesn't crash."
	time.Sleep(200 * time.Millisecond)
}
