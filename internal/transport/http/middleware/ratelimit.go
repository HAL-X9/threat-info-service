package middleware

import (
	"math"
	"net/http"
	"strconv"
	"sync"

	"golang.org/x/time/rate"
)

func RateLimit(requestsPerSecond float64, burst int) func(http.Handler) http.Handler {
	var limiters sync.Map

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limiter, _ := limiters.LoadOrStore(remoteIP(r), rate.NewLimiter(rate.Limit(requestsPerSecond), burst))

			reservation := limiter.(*rate.Limiter).Reserve()
			if delay := reservation.Delay(); delay > 0 {
				reservation.Cancel()
				w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(delay.Seconds()))))
				writeError(w, http.StatusTooManyRequests, "Too many requests")

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
