//go:build e2e

package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func baseURL(t *testing.T) string {
	t.Helper()

	base := os.Getenv("E2E_BASE_URL")
	if base == "" {
		base = "http://localhost:8080"
	}

	if code, _ := call(t, http.MethodGet, base+"/readyz", ""); code != http.StatusOK {
		t.Fatalf("the service at %s is not ready: start it with `make up`", base)
	}

	return base
}

func token() string {
	if token := os.Getenv("E2E_API_TOKEN"); token != "" {
		return token
	}

	return "local-dev-token-1234"
}

func call(t *testing.T, method, url, body string) (int, map[string]any) {
	t.Helper()

	return callAs(t, "Bearer "+token(), method, url, body)
}

func callAs(t *testing.T, authorization, method, url, body string) (int, map[string]any) {
	t.Helper()

	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(t.Context(), method, url, strings.NewReader(body))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}

		req.Header.Set("Content-Type", "application/json")

		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, url, err)
		}

		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusTooManyRequests || attempt == 3 {
			return resp.StatusCode, out
		}

		time.Sleep(time.Second)
	}
}

func newHash(t *testing.T) string {
	t.Helper()

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random hash: %v", err)
	}

	return hex.EncodeToString(b)
}

func post(t *testing.T, base, md5, name string) (int, map[string]any) {
	t.Helper()

	body := `{"md5":"` + md5 + `","name":"` + name + `","severity":"high","category":"trojan","tags":["Dropper","dropper"]}`

	return call(t, http.MethodPost, base+"/info", body)
}

func want(t *testing.T, got, expected int, body map[string]any) {
	t.Helper()

	if got != expected {
		t.Fatalf("status = %d, want %d: %v", got, expected, body)
	}
}

func TestCreateAndRetrieveAThreat(t *testing.T) {
	base := baseURL(t)
	md5 := newHash(t)

	code, created := post(t, base, strings.ToUpper(md5), " Trojan.Win32.Generic ")
	want(t, code, http.StatusCreated, created)

	if created["md5"] != md5 || created["name"] != "Trojan.Win32.Generic" || !reflect.DeepEqual(created["tags"], []any{"dropper"}) {
		t.Errorf("created = %v, want the lowercase hash, the trimmed name and the deduplicated tags", created)
	}

	for _, hash := range []string{md5, strings.ToUpper(md5)} {
		code, got := call(t, http.MethodGet, base+"/info/"+hash, "")
		want(t, code, http.StatusOK, got)

		if !reflect.DeepEqual(got, created) {
			t.Errorf("GET %s = %v, want %v", hash, got, created)
		}
	}
}

func TestUpdateAThreat(t *testing.T) {
	base := baseURL(t)
	md5 := newHash(t)

	code, created := post(t, base, md5, "Original")
	want(t, code, http.StatusCreated, created)

	time.Sleep(10 * time.Millisecond)

	code, updated := call(t, http.MethodPut, base+"/info/"+md5, `{"name":"Renamed","severity":"low","category":"worm"}`)
	want(t, code, http.StatusOK, updated)

	if updated["name"] != "Renamed" || updated["category"] != "worm" || updated["created_at"] != created["created_at"] {
		t.Errorf("updated = %v, want the new details and the original created_at", updated)
	}

	if tags, _ := updated["tags"].([]any); len(tags) != 0 {
		t.Errorf("tags = %v, want the omitted field cleared", updated["tags"])
	}

	createdAt, _ := time.Parse(time.RFC3339Nano, created["created_at"].(string))
	updatedAt, _ := time.Parse(time.RFC3339Nano, updated["updated_at"].(string))

	if !updatedAt.After(createdAt) {
		t.Errorf("updated_at = %v, want it after created_at %v", updatedAt, createdAt)
	}

	code, got := call(t, http.MethodGet, base+"/info/"+md5, "")
	want(t, code, http.StatusOK, got)

	if !reflect.DeepEqual(got, updated) {
		t.Errorf("GET = %v, want %v", got, updated)
	}
}

func TestDuplicateCreateIsRejected(t *testing.T) {
	base := baseURL(t)
	md5 := newHash(t)

	code, created := post(t, base, md5, "Original")
	want(t, code, http.StatusCreated, created)

	code, body := post(t, base, md5, "Other")
	want(t, code, http.StatusConflict, body)

	code, got := call(t, http.MethodGet, base+"/info/"+md5, "")
	want(t, code, http.StatusOK, got)

	if got["name"] != "Original" {
		t.Errorf("name = %v, want the original threat to be kept", got["name"])
	}
}

func TestMissingThreat(t *testing.T) {
	base := baseURL(t)
	md5 := newHash(t)

	code, body := call(t, http.MethodGet, base+"/info/"+md5, "")
	want(t, code, http.StatusNotFound, body)

	code, body = call(t, http.MethodPut, base+"/info/"+md5, `{"name":"x","severity":"low","category":"worm"}`)
	want(t, code, http.StatusNotFound, body)

	code, body = call(t, http.MethodGet, base+"/info/"+md5, "")
	want(t, code, http.StatusNotFound, body)
}

func TestInvalidInputIsRejectedAndNotStored(t *testing.T) {
	base := baseURL(t)
	md5 := newHash(t)

	invalid := `{"md5":"` + md5 + `","name":"x","severity":"urgent","category":"trojan"}`

	code, body := call(t, http.MethodPost, base+"/info", invalid)
	want(t, code, http.StatusBadRequest, body)

	if msg, _ := body["message"].(string); msg == "" {
		t.Errorf("body = %v, want an ErrorResponse with a message", body)
	}

	code, body = call(t, http.MethodGet, base+"/info/"+md5, "")
	want(t, code, http.StatusNotFound, body)

	code, body = call(t, http.MethodGet, base+"/info/not-a-hash", "")
	want(t, code, http.StatusBadRequest, body)

	unknown := `{"md5":"` + md5 + `","name":"x","severity":"low","category":"worm","extra":1}`

	code, body = call(t, http.MethodPost, base+"/info", unknown)
	want(t, code, http.StatusBadRequest, body)

	code, body = call(t, http.MethodGet, base+"/info/"+md5, "")
	want(t, code, http.StatusNotFound, body)
}

func TestWritesRequireAToken(t *testing.T) {
	base := baseURL(t)
	md5 := newHash(t)

	body := `{"md5":"` + md5 + `","name":"x","severity":"low","category":"worm"}`

	for _, authorization := range []string{"", "Bearer wrong-token-0123456789"} {
		code, got := callAs(t, authorization, http.MethodPost, base+"/info", body)
		want(t, code, http.StatusUnauthorized, got)
	}

	code, got := call(t, http.MethodGet, base+"/info/"+md5, "")
	want(t, code, http.StatusNotFound, got)

	code, got = post(t, base, md5, "Authorized")
	want(t, code, http.StatusCreated, got)

	code, got = callAs(t, "", http.MethodGet, base+"/info/"+md5, "")
	want(t, code, http.StatusOK, got)

	code, got = callAs(t, "", http.MethodPut, base+"/info/"+md5, `{"name":"x","severity":"low","category":"worm"}`)
	want(t, code, http.StatusUnauthorized, got)
}
