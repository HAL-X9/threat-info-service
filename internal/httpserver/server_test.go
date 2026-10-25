package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/config"
)

func httpConfig(addr string) config.HTTPServer {
	return config.HTTPServer{
		Addr: addr,
		Timeouts: config.HTTPTimeouts{
			ReadTimeout:       time.Second,
			ReadHeaderTimeout: time.Second,
			WriteTimeout:      time.Second,
			IdleTimeout:       time.Second,
		},
	}
}

func newServerWith(t *testing.T, cfg config.HTTPServer, logs *bytes.Buffer) *Server {
	t.Helper()

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	srv, err := New(cfg, handler, slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return srv
}

func newServer(t *testing.T, addr string, logs *bytes.Buffer) *Server {
	t.Helper()

	return newServerWith(t, httpConfig(addr), logs)
}

// messages returns the msg field of every JSON log line.
func messages(t *testing.T, logs *bytes.Buffer) []string {
	t.Helper()

	var msgs []string

	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var rec struct {
			Msg string `json:"msg"`
		}

		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v: %q", err, line)
		}

		msgs = append(msgs, rec.Msg)
	}

	return msgs
}

func freeAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	defer func() { _ = ln.Close() }()

	return ln.Addr().String()
}

func TestRunServesAndStopsOnCancel(t *testing.T) {
	addr := freeAddr(t)

	var logs bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- newServer(t, addr, &logs).Run(ctx) }()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	deadline := time.Now().Add(3 * time.Second)

	for {
		resp, err := client.Get("http://" + addr)
		if err == nil {
			_ = resp.Body.Close()

			break
		}

		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}

		time.Sleep(10 * time.Millisecond)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil after a requested shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s")
	}

	if conn, err := net.Dial("tcp", addr); err == nil {
		_ = conn.Close()
		t.Error("the server still accepts connections after Run returned")
	}

	want := []string{"http server ready", "http server shutting down", "http server stopped"}
	if got := messages(t, &logs); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("log messages = %q, want %q", got, want)
	}

	if !strings.Contains(logs.String(), addr) {
		t.Errorf("the ready message does not name the address %s: %q", addr, logs.String())
	}
}

func TestRunFailsWhenAddressIsTaken(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy address: %v", err)
	}
	defer func() { _ = taken.Close() }()

	var logs bytes.Buffer

	if err = newServer(t, taken.Addr().String(), &logs).Run(context.Background()); err == nil {
		t.Fatal("Run succeeded although the address was taken, want an error")
	}

	if strings.Contains(logs.String(), "ready") {
		t.Errorf("the server reported ready although it could not bind: %q", logs.String())
	}
}
