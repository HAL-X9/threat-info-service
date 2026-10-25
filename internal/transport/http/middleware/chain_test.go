package middleware

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestChainRunsTheFirstMiddlewareOutermost(t *testing.T) {
	var calls []string

	mark := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	handler := Chain(mark("first"), mark("second"), mark("third"))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls = append(calls, "handler")
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if want := []string{"first", "second", "third", "handler"}; !slices.Equal(calls, want) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
}

func TestEmptyChainReturnsTheHandler(t *testing.T) {
	called := false

	Chain()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if !called {
		t.Error("the handler was not called")
	}
}
