package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/HAL-X9/threat-info-service/internal/transport/http/gen"
)

const (
	hash        = "d41d8cd98f00b204e9800998ecf8427e"
	token       = "local-test-token-12345"
	validCreate = `{"md5":"` + hash + `","name":"Trojan","severity":"high","category":"trojan","tags":["a","b"]}`
	validUpdate = `{"name":"Renamed","severity":"low","category":"worm"}`
)

type outcome struct {
	called bool
	body   string
	rec    *httptest.ResponseRecorder
}

func validate(t *testing.T, method, path, authorization, body string) outcome {
	t.Helper()

	spec, err := gen.GetSpec()
	if err != nil {
		t.Fatalf("load the spec: %v", err)
	}

	var out outcome

	handler := OpenAPI(spec, token)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out.called = true
		data, _ := io.ReadAll(r.Body)
		out.body = string(data)
	}))

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	out.rec = httptest.NewRecorder()
	handler.ServeHTTP(out.rec, req)

	return out
}

func wantError(t *testing.T, out outcome, status int) map[string]any {
	t.Helper()

	if out.rec.Code != status || out.called {
		t.Fatalf("status = %d, handler called = %v, want %d and not called: %s", out.rec.Code, out.called, status, out.rec.Body)
	}

	if got := out.rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var body map[string]any
	if err := json.Unmarshal(out.rec.Body.Bytes(), &body); err != nil || body["message"] == "" {
		t.Errorf("body = %q, want an ErrorResponse with a message (%v)", out.rec.Body, err)
	}

	return body
}

func TestOpenAPIPassesValidAuthorizedRequests(t *testing.T) {
	tests := map[string]struct {
		method string
		path   string
		body   string
	}{
		"create":  {http.MethodPost, "/info", validCreate},
		"replace": {http.MethodPut, "/info/" + hash, validUpdate},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			out := validate(t, tc.method, tc.path, "Bearer "+token, tc.body)

			if !out.called || out.body != tc.body {
				t.Errorf("called = %v, body = %q, want the handler to receive %q", out.called, out.body, tc.body)
			}
		})
	}
}

func TestOpenAPILeavesReadsOpen(t *testing.T) {
	if out := validate(t, http.MethodGet, "/info/"+hash, "", ""); !out.called {
		t.Errorf("status = %d, want a read without a token to pass", out.rec.Code)
	}
}

func TestOpenAPIRejectsMissingOrWrongTokens(t *testing.T) {
	for name, authorization := range map[string]string{
		"no header":      "",
		"wrong token":    "Bearer wrong-token-0123456789",
		"other scheme":   "Basic " + token,
		"token only":     token,
		"empty bearer":   "Bearer ",
		"truncated":      "Bearer " + token[:10],
		"token extended": "Bearer " + token + "x",
	} {
		for _, method := range []string{http.MethodPost, http.MethodPut} {
			t.Run(name+" "+method, func(t *testing.T) {
				path, body := "/info", validCreate
				if method == http.MethodPut {
					path, body = "/info/"+hash, validUpdate
				}

				out := validate(t, method, path, authorization, body)
				wantError(t, out, http.StatusUnauthorized)

				if got := out.rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
					t.Errorf("WWW-Authenticate = %q, want Bearer", got)
				}
			})
		}
	}
}

func TestOpenAPIAuthenticatesBeforeItValidatesTheBody(t *testing.T) {
	wantError(t, validate(t, http.MethodPost, "/info", "", `{"unknown":1}`), http.StatusUnauthorized)
}

func TestOpenAPIRejectsRequestsThatBreakTheSchema(t *testing.T) {
	tests := map[string]struct {
		method string
		path   string
		body   string
	}{
		"unknown field on create":  {http.MethodPost, "/info", strings.Replace(validCreate, `"name"`, `"extra":1,"name"`, 1)},
		"unknown field on replace": {http.MethodPut, "/info/" + hash, strings.Replace(validUpdate, `"name"`, `"extra":1,"name"`, 1)},
		"md5 in a replace body":    {http.MethodPut, "/info/" + hash, `{"md5":"` + hash + `","name":"x","severity":"low","category":"worm"}`},
		"missing name":             {http.MethodPost, "/info", `{"md5":"` + hash + `","severity":"high","category":"trojan"}`},
		"missing md5":              {http.MethodPost, "/info", `{"name":"x","severity":"high","category":"trojan"}`},
		"wrong type":               {http.MethodPost, "/info", `{"md5":"` + hash + `","name":5,"severity":"high","category":"trojan"}`},
		"unknown severity":         {http.MethodPost, "/info", `{"md5":"` + hash + `","name":"x","severity":"urgent","category":"trojan"}`},
		"short md5":                {http.MethodPost, "/info", `{"md5":"abc","name":"x","severity":"high","category":"trojan"}`},
		"empty name":               {http.MethodPost, "/info", `{"md5":"` + hash + `","name":"","severity":"high","category":"trojan"}`},
		"name over 255":            {http.MethodPost, "/info", `{"md5":"` + hash + `","name":"` + strings.Repeat("x", 256) + `","severity":"high","category":"trojan"}`},
		"duplicate tags":           {http.MethodPost, "/info", `{"md5":"` + hash + `","name":"x","severity":"high","category":"trojan","tags":["a","a"]}`},
		"malformed json":           {http.MethodPost, "/info", `{"md5":`},
		"empty body":               {http.MethodPost, "/info", ``},
		"invalid md5 in the path":  {http.MethodGet, "/info/abc", ``},
		"too long md5 in the path": {http.MethodGet, "/info/" + hash + "0", ``},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			body := wantError(t, validate(t, tc.method, tc.path, "Bearer "+token, tc.body), http.StatusBadRequest)

			details, _ := body["details"].(string)
			if details == "" || strings.Contains(details, "\n") || strings.Contains(details, "Schema:") {
				t.Errorf("details = %q, want a one-line reason without the schema or the value", details)
			}
		})
	}
}

func TestOpenAPIAnswersUnknownRoutesAndMethods(t *testing.T) {
	wantError(t, validate(t, http.MethodGet, "/nope", "", ""), http.StatusNotFound)
	wantError(t, validate(t, http.MethodGet, "/info/"+hash+"/extra", "", ""), http.StatusNotFound)
	wantError(t, validate(t, http.MethodDelete, "/info/"+hash, "Bearer "+token, ""), http.StatusMethodNotAllowed)
}

func TestOpenAPIReportsAnOversizedStreamedBodyAs413(t *testing.T) {
	spec, err := gen.GetSpec()
	if err != nil {
		t.Fatalf("load the spec: %v", err)
	}

	handler := Chain(MaxBody(20), OpenAPI(spec, token))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the handler ran for an oversized body")
	}))

	req := httptest.NewRequest(http.MethodPost, "/info", io.NopCloser(strings.NewReader(validCreate)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d: %s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body)
	}
}
