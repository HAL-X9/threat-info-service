package threat_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HAL-X9/threat-info-service/internal/domain"
	"github.com/HAL-X9/threat-info-service/internal/service"
	"github.com/HAL-X9/threat-info-service/internal/transport/http/threat"
)

const (
	md5      = "d41d8cd98f00b204e9800998ecf8427e"
	validNew = `{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic","severity":"high","category":"trojan","description":"Drops modules","tags":["Dropper"]}`
	validPut = `{"name":"Renamed","severity":"low","category":"worm"}`
)

var now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newMux(svc threat.Service, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	threat.NewHandler(svc, log).Register(mux)

	return mux
}

func newRealMux() http.Handler {
	return newMux(service.New(newFakeRepo(), func() time.Time { return now }), discardLogger())
}

func do(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not a JSON object: %v: %q", err, rec.Body.String())
	}

	return out
}

func wantError(t *testing.T, rec *httptest.ResponseRecorder, status int) map[string]any {
	t.Helper()

	if rec.Code != status {
		t.Fatalf("status = %d, want %d: %s", rec.Code, status, rec.Body.String())
	}

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	body := decode(t, rec)
	if msg, _ := body["message"].(string); msg == "" {
		t.Errorf("body = %v, want an ErrorResponse with a message", body)
	}

	return body
}

func TestCreate(t *testing.T) {
	rec := do(newRealMux(), http.MethodPost, "/info", validNew)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	body := decode(t, rec)
	want := map[string]any{
		"md5":         md5,
		"name":        "Trojan.Win32.Generic",
		"severity":    "high",
		"category":    "trojan",
		"description": "Drops modules",
		"created_at":  "2026-10-25T12:00:00Z",
		"updated_at":  "2026-10-25T12:00:00Z",
	}

	for key, v := range want {
		if body[key] != v {
			t.Errorf("%s = %v, want %v", key, body[key], v)
		}
	}

	if tags, _ := body["tags"].([]any); len(tags) != 1 || tags[0] != "dropper" {
		t.Errorf("tags = %v, want the tags lowercased", body["tags"])
	}
}

func TestCreateNormalizesTheMD5(t *testing.T) {
	mux := newRealMux()
	upper := strings.Replace(validNew, md5, strings.ToUpper(md5), 1)

	if rec := do(mux, http.MethodPost, "/info", upper); rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	rec := do(mux, http.MethodGet, "/info/"+md5, "")
	if rec.Code != http.StatusOK || decode(t, rec)["md5"] != md5 {
		t.Errorf("GET by the lowercase hash = %d %s, want the record stored in lowercase", rec.Code, rec.Body.String())
	}
}

func TestCreateOmitsAnEmptyDescriptionAndKeepsTagsAsAList(t *testing.T) {
	body := `{"md5":"` + md5 + `","name":"x","severity":"low","category":"other"}`

	rec := do(newRealMux(), http.MethodPost, "/info", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	out := decode(t, rec)
	if _, present := out["description"]; present {
		t.Errorf("description = %v, want it omitted", out["description"])
	}

	if tags, ok := out["tags"].([]any); !ok || len(tags) != 0 {
		t.Errorf("tags = %#v, want an empty list", out["tags"])
	}
}

func TestCreateConflict(t *testing.T) {
	mux := newRealMux()

	do(mux, http.MethodPost, "/info", validNew)

	wantError(t, do(mux, http.MethodPost, "/info", validNew), http.StatusConflict)
}

func TestCreateRejectsInvalidRequests(t *testing.T) {
	tests := map[string]string{
		"malformed json":      `{"md5":`,
		"empty body":          ``,
		"not an object":       `[]`,
		"wrong field type":    `{"md5":"` + md5 + `","name":5,"severity":"low","category":"other"}`,
		"missing md5":         `{"name":"x","severity":"low","category":"other"}`,
		"short md5":           `{"md5":"abc","name":"x","severity":"low","category":"other"}`,
		"non hexadecimal md5": `{"md5":"zzzd8cd98f00b204e9800998ecf8427e","name":"x","severity":"low","category":"other"}`,
		"missing name":        `{"md5":"` + md5 + `","severity":"low","category":"other"}`,
		"blank name":          `{"md5":"` + md5 + `","name":"  ","severity":"low","category":"other"}`,
		"unknown severity":    `{"md5":"` + md5 + `","name":"x","severity":"urgent","category":"other"}`,
		"unknown category":    `{"md5":"` + md5 + `","name":"x","severity":"low","category":"virus"}`,
		"too many tags":       `{"md5":"` + md5 + `","name":"x","severity":"low","category":"other","tags":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u"]}`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			mux := newRealMux()

			wantError(t, do(mux, http.MethodPost, "/info", body), http.StatusBadRequest)

			if rec := do(mux, http.MethodGet, "/info/"+md5, ""); rec.Code != http.StatusNotFound {
				t.Errorf("GET after a rejected create = %d, want %d: nothing must be stored", rec.Code, http.StatusNotFound)
			}
		})
	}
}

func TestGet(t *testing.T) {
	mux := newRealMux()

	do(mux, http.MethodPost, "/info", validNew)

	rec := do(mux, http.MethodGet, "/info/"+md5, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if body := decode(t, rec); body["md5"] != md5 || body["name"] != "Trojan.Win32.Generic" {
		t.Errorf("body = %v, want the stored threat", body)
	}
}

func TestGetFindsTheRecordRegardlessOfTheCaseInTheURL(t *testing.T) {
	mux := newRealMux()

	do(mux, http.MethodPost, "/info", validNew)

	if rec := do(mux, http.MethodGet, "/info/"+strings.ToUpper(md5), ""); rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestGetMissing(t *testing.T) {
	wantError(t, do(newRealMux(), http.MethodGet, "/info/"+md5, ""), http.StatusNotFound)
}

func TestGetRejectsAnInvalidMD5(t *testing.T) {
	for name, path := range map[string]string{
		"short":           "/info/abc",
		"not hexadecimal": "/info/zzzd8cd98f00b204e9800998ecf8427e",
		"too long":        "/info/" + md5 + "0",
	} {
		t.Run(name, func(t *testing.T) {
			wantError(t, do(newRealMux(), http.MethodGet, path, ""), http.StatusBadRequest)
		})
	}
}

func TestUpdateReplacesTheRecord(t *testing.T) {
	mux := newRealMux()

	do(mux, http.MethodPost, "/info", validNew)

	rec := do(mux, http.MethodPut, "/info/"+md5, validPut)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body := decode(t, rec)
	if body["md5"] != md5 || body["name"] != "Renamed" || body["severity"] != "low" || body["category"] != "worm" {
		t.Errorf("body = %v, want the replaced details under the same md5", body)
	}

	if _, present := body["description"]; present {
		t.Errorf("description = %v, want the omitted field to be cleared", body["description"])
	}

	if tags, _ := body["tags"].([]any); len(tags) != 0 {
		t.Errorf("tags = %v, want the omitted field to be cleared", body["tags"])
	}

	if body["created_at"] != "2026-10-25T12:00:00Z" {
		t.Errorf("created_at = %v, want it unchanged", body["created_at"])
	}
}

func TestUpdateMissing(t *testing.T) {
	wantError(t, do(newRealMux(), http.MethodPut, "/info/"+md5, validPut), http.StatusNotFound)
}

func TestUpdateRejectsInvalidRequests(t *testing.T) {
	tests := map[string]struct {
		path string
		body string
	}{
		"invalid md5":      {"/info/abc", validPut},
		"malformed json":   {"/info/" + md5, `{"name":`},
		"empty body":       {"/info/" + md5, ``},
		"missing name":     {"/info/" + md5, `{"severity":"low","category":"worm"}`},
		"unknown severity": {"/info/" + md5, `{"name":"x","severity":"urgent","category":"worm"}`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mux := newRealMux()

			do(mux, http.MethodPost, "/info", validNew)

			wantError(t, do(mux, http.MethodPut, tc.path, tc.body), http.StatusBadRequest)

			if body := decode(t, do(mux, http.MethodGet, "/info/"+md5, "")); body["name"] != "Trojan.Win32.Generic" {
				t.Errorf("name = %v, want the record untouched by a rejected update", body["name"])
			}
		})
	}
}

func TestOversizedBodyIsReportedAs413(t *testing.T) {
	mux := newRealMux()

	req := httptest.NewRequest(http.MethodPost, "/info", io.NopCloser(strings.NewReader(validNew)))
	req.ContentLength = -1

	rec := httptest.NewRecorder()
	limited := http.MaxBytesHandler(mux, 10)
	limited.ServeHTTP(rec, req)

	wantError(t, rec, http.StatusRequestEntityTooLarge)
}

type failingService struct{ err error }

func (s failingService) Create(context.Context, domain.MD5, domain.Details) (domain.Threat, error) {
	return domain.Threat{}, s.err
}

func (s failingService) Get(context.Context, domain.MD5) (domain.Threat, error) {
	return domain.Threat{}, s.err
}

func (s failingService) Update(context.Context, domain.MD5, domain.Details) (domain.Threat, error) {
	return domain.Threat{}, s.err
}

func TestUnexpectedErrorsAre500AndDoNotLeakTheCause(t *testing.T) {
	var logs bytes.Buffer

	cause := errors.New("connection to 10.0.0.5 refused")
	mux := newMux(failingService{err: cause}, slog.New(slog.NewJSONHandler(&logs, nil)))

	requests := map[string]*httptest.ResponseRecorder{
		"create": do(mux, http.MethodPost, "/info", validNew),
		"get":    do(mux, http.MethodGet, "/info/"+md5, ""),
		"update": do(mux, http.MethodPut, "/info/"+md5, validPut),
	}

	for name, rec := range requests {
		t.Run(name, func(t *testing.T) {
			wantError(t, rec, http.StatusInternalServerError)

			if strings.Contains(rec.Body.String(), "10.0.0.5") {
				t.Errorf("body leaks the cause: %s", rec.Body.String())
			}
		})
	}

	if got := strings.Count(logs.String(), "10.0.0.5"); got != len(requests) {
		t.Errorf("the cause appears in the log %d times, want once per failed request (%d)", got, len(requests))
	}
}

func TestValidationErrorsExplainWhatIsWrong(t *testing.T) {
	rec := do(newRealMux(), http.MethodPost, "/info", `{"md5":"`+md5+`","name":"x","severity":"urgent","category":"other"}`)

	body := wantError(t, rec, http.StatusBadRequest)
	if details, _ := body["details"].(string); !strings.Contains(details, "severity") {
		t.Errorf("details = %v, want it to mention the severity", body["details"])
	}
}

type fakeRepo struct{ threats map[domain.MD5]domain.Threat }

func newFakeRepo() *fakeRepo {
	return &fakeRepo{threats: make(map[domain.MD5]domain.Threat)}
}

func (r *fakeRepo) Create(_ context.Context, threat domain.Threat) (domain.Threat, error) {
	if _, exists := r.threats[threat.MD5]; exists {
		return domain.Threat{}, domain.ErrConflict
	}

	r.threats[threat.MD5] = threat

	return threat, nil
}

func (r *fakeRepo) Get(_ context.Context, md5 domain.MD5) (domain.Threat, error) {
	threat, exists := r.threats[md5]
	if !exists {
		return domain.Threat{}, domain.ErrNotFound
	}

	return threat, nil
}

func (r *fakeRepo) Update(_ context.Context, md5 domain.MD5, details domain.Details, now time.Time) (domain.Threat, error) {
	threat, exists := r.threats[md5]
	if !exists {
		return domain.Threat{}, domain.ErrNotFound
	}

	threat.Details = details
	threat.UpdatedAt = now
	r.threats[md5] = threat

	return threat, nil
}
