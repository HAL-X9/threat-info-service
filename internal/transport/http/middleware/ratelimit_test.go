package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

var ok = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

func hit(handler http.Handler, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	req.RemoteAddr = remoteAddr

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec
}

func TestRateLimitAllowsABurstThenRejects(t *testing.T) {
	handler := RateLimit(1, 3)(ok)

	for i := range 3 {
		if got := hit(handler, "192.0.2.1:1000").Code; got != http.StatusOK {
			t.Fatalf("request %d = %d, want %d", i+1, got, http.StatusOK)
		}
	}

	if got := hit(handler, "192.0.2.1:1000").Code; got != http.StatusTooManyRequests {
		t.Fatalf("request over the burst = %d, want %d", got, http.StatusTooManyRequests)
	}
}

func TestRateLimitRejectionIsAnErrorResponseWithRetryAfter(t *testing.T) {
	handler := RateLimit(0.5, 1)(ok)

	hit(handler, "192.0.2.1:1000")
	rec := hit(handler, "192.0.2.1:1000")

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var body struct{ Message string }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Message == "" {
		t.Errorf("body = %q, want an ErrorResponse with a message (%v)", rec.Body.String(), err)
	}

	if got := rec.Header().Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q, want 2 for a rate of one request per 2 seconds", got)
	}
}

func TestRateLimitTracksClientsSeparately(t *testing.T) {
	handler := RateLimit(1, 1)(ok)

	hit(handler, "192.0.2.1:1000")

	if got := hit(handler, "192.0.2.1:2000").Code; got != http.StatusTooManyRequests {
		t.Errorf("same address, other port = %d, want %d: the port must not matter", got, http.StatusTooManyRequests)
	}

	if got := hit(handler, "192.0.2.2:1000").Code; got != http.StatusOK {
		t.Errorf("other address = %d, want %d", got, http.StatusOK)
	}
}

func TestRateLimitRefillsOverTime(t *testing.T) {
	handler := RateLimit(rate.Every(20*time.Millisecond), 1)(ok)

	hit(handler, "192.0.2.1:1000")

	if got := hit(handler, "192.0.2.1:1000").Code; got != http.StatusTooManyRequests {
		t.Fatalf("immediate retry = %d, want %d", got, http.StatusTooManyRequests)
	}

	time.Sleep(100 * time.Millisecond)

	if got := hit(handler, "192.0.2.1:1000").Code; got != http.StatusOK {
		t.Errorf("retry after the interval = %d, want %d", got, http.StatusOK)
	}
}

func TestRateLimitRejectedRequestsDoNotConsumeTokens(t *testing.T) {
	handler := RateLimit(rate.Every(50*time.Millisecond), 1)(ok)

	hit(handler, "192.0.2.1:1000")

	for range 20 {
		hit(handler, "192.0.2.1:1000")
	}

	time.Sleep(120 * time.Millisecond)

	if got := hit(handler, "192.0.2.1:1000").Code; got != http.StatusOK {
		t.Errorf("retry after the interval = %d, want %d: rejected requests must not delay the client further", got, http.StatusOK)
	}
}

func TestRateLimitIsSafeForConcurrentUse(t *testing.T) {
	handler := RateLimit(1000, 1000)(ok)

	var wg sync.WaitGroup

	for i := range 20 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for range 50 {
				hit(handler, "192.0.2."+strconv.Itoa(i)+":1000")
			}
		}()
	}

	wg.Wait()
}
