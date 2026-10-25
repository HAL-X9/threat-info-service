package middleware

import (
	"net/http"

	"github.com/google/uuid"
)

const (
	RequestIDHeader = "X-Request-Id"

	maxRequestIDLength = 128
)

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header[RequestIDHeader]
		if len(id) != 1 || !validRequestID(id[0]) {
			id = []string{uuid.Must(uuid.NewV7()).String()}
			r.Header[RequestIDHeader] = id
		}

		w.Header()[RequestIDHeader] = id

		next.ServeHTTP(w, r)
	})
}

func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLength {
		return false
	}

	for i := 0; i < len(id); i++ {
		if id[i] < '!' || id[i] > '~' {
			return false
		}
	}

	return true
}
