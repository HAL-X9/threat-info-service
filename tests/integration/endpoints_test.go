//go:build integration

package integration

import (
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCreateThreat(t *testing.T) {
	base := newAPI(t)

	t.Run("stores a normalized threat", func(t *testing.T) {
		md5 := hashN(1)
		body := `{"md5":"` + strings.ToUpper(md5) + `","name":" Trojan ","severity":"high","category":"trojan",` +
			`"description":"Drops modules","tags":["Dropper","dropper"]}`

		code, created := call(t, http.MethodPost, base+"/info", body)
		wantStatus(t, code, http.StatusCreated, created)

		want := map[string]any{"md5": md5, "name": "Trojan", "description": "Drops modules", "severity": "high", "category": "trojan"}
		for key, v := range want {
			if created[key] != v {
				t.Errorf("%s = %v, want %v", key, created[key], v)
			}
		}

		if !reflect.DeepEqual(created["tags"], []any{"dropper"}) {
			t.Errorf("tags = %v, want the tags lowercased and deduplicated", created["tags"])
		}

		if created["created_at"] != created["updated_at"] {
			t.Errorf("created_at = %v, updated_at = %v, want them equal", created["created_at"], created["updated_at"])
		}

		if code, got := call(t, http.MethodGet, base+"/info/"+md5, ""); code != http.StatusOK || !reflect.DeepEqual(got, created) {
			t.Errorf("GET = %d %v, want the stored threat %v", code, got, created)
		}
	})

	t.Run("defaults the optional fields", func(t *testing.T) {
		created := createThreat(t, base, hashN(2), "Plain")

		if _, present := created["description"]; present {
			t.Errorf("description = %v, want it omitted", created["description"])
		}

		if tags, ok := created["tags"].([]any); !ok || len(tags) != 0 {
			t.Errorf("tags = %#v, want an empty list", created["tags"])
		}
	})

	t.Run("rejects a duplicate hash", func(t *testing.T) {
		createThreat(t, base, hashN(3), "Original")

		code, body := call(t, http.MethodPost, base+"/info", threatJSON(hashN(3), "Other"))
		wantStatus(t, code, http.StatusConflict, body)
		wantMessage(t, body)

		if _, got := call(t, http.MethodGet, base+"/info/"+hashN(3), ""); got["name"] != "Original" {
			t.Errorf("name = %v, want the original to be kept", got["name"])
		}
	})

	t.Run("lets one of many concurrent creates win", func(t *testing.T) {
		const workers = 20

		var (
			wg    sync.WaitGroup
			mu    sync.Mutex
			codes = make(map[int]int)
		)

		for range workers {
			wg.Add(1)

			go func() {
				defer wg.Done()

				req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/info", strings.NewReader(threatJSON(hashN(4), "race")))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+apiToken)

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return
				}
				_ = resp.Body.Close()

				mu.Lock()
				codes[resp.StatusCode]++
				mu.Unlock()
			}()
		}

		wg.Wait()

		if codes[http.StatusCreated] != 1 || codes[http.StatusConflict] != workers-1 {
			t.Errorf("status counts = %v, want one 201 and %d 409", codes, workers-1)
		}
	})

	t.Run("requires a valid token and stores nothing without it", func(t *testing.T) {
		md5 := hashN(6)

		for _, authorization := range []string{"", "Bearer wrong-token-0123456789"} {
			code, body := callAs(t, authorization, http.MethodPost, base+"/info", threatJSON(md5, "x"))
			wantStatus(t, code, http.StatusUnauthorized, body)
			wantMessage(t, body)
		}

		if code, _ := call(t, http.MethodGet, base+"/info/"+md5, ""); code != http.StatusNotFound {
			t.Errorf("GET = %d, want %d: an unauthorized request must store nothing", code, http.StatusNotFound)
		}
	})

	t.Run("rejects fields the contract does not define", func(t *testing.T) {
		md5 := hashN(7)
		body := `{"md5":"` + md5 + `","name":"x","severity":"low","category":"worm","extra":1}`

		code, got := call(t, http.MethodPost, base+"/info", body)
		wantStatus(t, code, http.StatusBadRequest, got)
		wantMessage(t, got)

		if code, _ = call(t, http.MethodGet, base+"/info/"+md5, ""); code != http.StatusNotFound {
			t.Errorf("GET = %d, want %d: nothing must be stored", code, http.StatusNotFound)
		}
	})

	t.Run("rejects invalid input and stores nothing", func(t *testing.T) {
		md5 := hashN(5)

		tests := map[string]string{
			"malformed json":   `{"md5":`,
			"missing hash":     `{"name":"x","severity":"low","category":"worm"}`,
			"short hash":       `{"md5":"abc","name":"x","severity":"low","category":"worm"}`,
			"blank name":       `{"md5":"` + md5 + `","name":"  ","severity":"low","category":"worm"}`,
			"unknown severity": `{"md5":"` + md5 + `","name":"x","severity":"urgent","category":"worm"}`,
			"unknown category": `{"md5":"` + md5 + `","name":"x","severity":"low","category":"virus"}`,
			"too many tags": `{"md5":"` + md5 + `","name":"x","severity":"low","category":"worm",` +
				`"tags":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u"]}`,
		}

		for name, body := range tests {
			t.Run(name, func(t *testing.T) {
				code, got := call(t, http.MethodPost, base+"/info", body)
				wantStatus(t, code, http.StatusBadRequest, got)
				wantMessage(t, got)
			})
		}

		if code, _ := call(t, http.MethodGet, base+"/info/"+md5, ""); code != http.StatusNotFound {
			t.Errorf("GET = %d, want %d: a rejected request must store nothing", code, http.StatusNotFound)
		}
	})
}

func TestGetThreat(t *testing.T) {
	base := newAPI(t)
	created := createThreat(t, base, hashN(1), "Stored")

	t.Run("returns a stored threat", func(t *testing.T) {
		code, got := call(t, http.MethodGet, base+"/info/"+hashN(1), "")
		wantStatus(t, code, http.StatusOK, got)

		if !reflect.DeepEqual(got, created) {
			t.Errorf("body = %v, want %v", got, created)
		}
	})

	t.Run("ignores the case of the hash", func(t *testing.T) {
		code, got := call(t, http.MethodGet, base+"/info/"+strings.ToUpper(hashN(1)), "")
		wantStatus(t, code, http.StatusOK, got)

		if got["md5"] != hashN(1) {
			t.Errorf("md5 = %v, want %v", got["md5"], hashN(1))
		}
	})

	t.Run("needs no token", func(t *testing.T) {
		code, got := callAs(t, "", http.MethodGet, base+"/info/"+hashN(1), "")
		wantStatus(t, code, http.StatusOK, got)
	})

	t.Run("answers 404 for an unknown hash", func(t *testing.T) {
		code, got := call(t, http.MethodGet, base+"/info/"+hashN(2), "")
		wantStatus(t, code, http.StatusNotFound, got)
		wantMessage(t, got)
	})

	t.Run("answers 400 for an invalid hash", func(t *testing.T) {
		for name, path := range map[string]string{
			"too short":       "abc",
			"not hexadecimal": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			"too long":        hashN(1) + "0",
		} {
			t.Run(name, func(t *testing.T) {
				code, got := call(t, http.MethodGet, base+"/info/"+path, "")
				wantStatus(t, code, http.StatusBadRequest, got)
				wantMessage(t, got)
			})
		}
	})
}

func TestUpdateThreat(t *testing.T) {
	base := newAPI(t)

	t.Run("replaces the details and keeps the identity", func(t *testing.T) {
		md5 := hashN(1)
		created := createThreat(t, base, md5, "Original")

		time.Sleep(10 * time.Millisecond)

		code, replaced := call(t, http.MethodPut, base+"/info/"+md5, putJSON("Renamed"))
		wantStatus(t, code, http.StatusOK, replaced)

		if replaced["md5"] != md5 || replaced["name"] != "Renamed" || replaced["category"] != "worm" || replaced["severity"] != "low" {
			t.Errorf("replaced = %v, want the new details under the same hash", replaced)
		}

		if replaced["created_at"] != created["created_at"] {
			t.Errorf("created_at = %v, want it unchanged (%v)", replaced["created_at"], created["created_at"])
		}

		createdAt, _ := time.Parse(time.RFC3339Nano, created["created_at"].(string))
		updatedAt, _ := time.Parse(time.RFC3339Nano, replaced["updated_at"].(string))

		if !updatedAt.After(createdAt) {
			t.Errorf("updated_at = %v, want it after created_at %v", updatedAt, createdAt)
		}

		if _, present := replaced["description"]; present || len(replaced["tags"].([]any)) != 0 {
			t.Errorf("replaced = %v, want the omitted fields cleared", replaced)
		}

		if code, got := call(t, http.MethodGet, base+"/info/"+md5, ""); code != http.StatusOK || !reflect.DeepEqual(got, replaced) {
			t.Errorf("GET = %d %v, want %v", code, got, replaced)
		}
	})

	t.Run("requires a valid token and keeps the record without it", func(t *testing.T) {
		md5 := hashN(4)
		createThreat(t, base, md5, "Original")

		for _, authorization := range []string{"", "Bearer wrong-token-0123456789"} {
			code, got := callAs(t, authorization, http.MethodPut, base+"/info/"+md5, putJSON("Hijacked"))
			wantStatus(t, code, http.StatusUnauthorized, got)
			wantMessage(t, got)
		}

		if _, got := call(t, http.MethodGet, base+"/info/"+md5, ""); got["name"] != "Original" {
			t.Errorf("name = %v, want the record untouched", got["name"])
		}
	})

	t.Run("rejects fields the contract does not define", func(t *testing.T) {
		md5 := hashN(5)
		createThreat(t, base, md5, "Original")

		code, got := call(t, http.MethodPut, base+"/info/"+md5, `{"name":"x","severity":"low","category":"worm","md5":"`+hashN(9)+`"}`)
		wantStatus(t, code, http.StatusBadRequest, got)
		wantMessage(t, got)
	})

	t.Run("answers 404 for an unknown hash", func(t *testing.T) {
		code, got := call(t, http.MethodPut, base+"/info/"+hashN(2), putJSON("x"))
		wantStatus(t, code, http.StatusNotFound, got)
		wantMessage(t, got)
	})

	t.Run("answers 400 for an invalid hash", func(t *testing.T) {
		code, got := call(t, http.MethodPut, base+"/info/abc", putJSON("x"))
		wantStatus(t, code, http.StatusBadRequest, got)
		wantMessage(t, got)
	})

	t.Run("rejects an invalid body and keeps the record", func(t *testing.T) {
		md5 := hashN(3)
		createThreat(t, base, md5, "Original")

		tests := map[string]string{
			"malformed json":   `{"name":`,
			"blank name":       `{"name":" ","severity":"low","category":"worm"}`,
			"unknown severity": `{"name":"x","severity":"urgent","category":"worm"}`,
		}

		for name, body := range tests {
			t.Run(name, func(t *testing.T) {
				code, got := call(t, http.MethodPut, base+"/info/"+md5, body)
				wantStatus(t, code, http.StatusBadRequest, got)
				wantMessage(t, got)
			})
		}

		if _, got := call(t, http.MethodGet, base+"/info/"+md5, ""); got["name"] != "Original" {
			t.Errorf("name = %v, want the record untouched", got["name"])
		}
	})
}
