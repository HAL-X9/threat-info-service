package threat

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/HAL-X9/threat-info-service/internal/domain"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/gen"
)

func (h *Handler) requestError(w http.ResponseWriter, _ *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "Request body too large", "")

		return
	}

	writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
}

func (h *Handler) responseError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrValidation):
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
	case errors.Is(err, domain.ErrNotFound):
		writeError(w, http.StatusNotFound, "Threat not found", "")
	case errors.Is(err, domain.ErrConflict):
		writeError(w, http.StatusConflict, "Threat already exists", "")
	default:
		h.log.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		writeError(w, http.StatusInternalServerError, "Internal server error", "")
	}
}

func writeError(w http.ResponseWriter, status int, message, details string) {
	resp := gen.ErrorResponse{Message: message}
	if details != "" {
		resp.Details = &details
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
