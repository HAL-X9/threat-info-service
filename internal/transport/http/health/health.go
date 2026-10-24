// Package health serves the operational endpoints of the service.
package health

import "net/http"

// Liveness reports that the process is alive.
func Liveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}
