package middleware

import (
	"encoding/json"
	"net/http"
)

func writeError(w http.ResponseWriter, status int, message string) {
	writeDetailedError(w, status, message, "")
}

func writeDetailedError(w http.ResponseWriter, status int, message, details string) {
	body := struct {
		Message string `json:"message"`
		Details string `json:"details,omitempty"`
	}{Message: message, Details: details}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
