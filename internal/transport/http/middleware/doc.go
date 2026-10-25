// Package middleware provides the HTTP middleware of the API: request
// identification, logging, recovery from panics, rate limiting, the limits on the size and the type of
// the body, and the validation of requests against the OpenAPI specification
// together with bearer authentication. Chain composes them in a given order.
package middleware
