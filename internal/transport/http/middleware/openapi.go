package middleware

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"
)

func OpenAPI(spec *openapi3.T, token string) func(http.Handler) http.Handler {
	return nethttpmiddleware.OapiRequestValidatorWithOptions(spec, &nethttpmiddleware.Options{
		Options:              openapi3filter.Options{AuthenticationFunc: bearer(token)},
		ErrorHandlerWithOpts: reject,
	})
}

func bearer(token string) openapi3filter.AuthenticationFunc {
	return func(_ context.Context, in *openapi3filter.AuthenticationInput) error {
		got, ok := strings.CutPrefix(in.RequestValidationInput.Request.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			return errors.New("bearer token is missing or invalid")
		}

		return nil
	}
}

func reject(_ context.Context, err error, w http.ResponseWriter, _ *http.Request, opts nethttpmiddleware.ErrorHandlerOpts) {
	var tooLarge *http.MaxBytesError

	switch {
	case opts.MatchedRoute == nil && errors.Is(err, routers.ErrMethodNotAllowed):
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	case opts.MatchedRoute == nil:
		writeError(w, http.StatusNotFound, "Route not found")
	case errors.As(err, &tooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "Request body too large")
	case opts.StatusCode == http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, "Unauthorized")
	case opts.StatusCode == http.StatusBadRequest:
		reason, _, _ := strings.Cut(err.Error(), "\n")
		writeDetailedError(w, http.StatusBadRequest, "Invalid request", reason)
	default:
		writeError(w, http.StatusInternalServerError, "Internal server error")
	}
}
