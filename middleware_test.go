package bearer_auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	bearer_auth "github.com/maruware/go-bearer-auth"
)

type hello struct{}

func (a *hello) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("hello"))
}

type ErrorResponse struct {
	Code string `json:"code"`
}

func TestMiddleware(t *testing.T) {
	token := "MY_TOKEN"
	h := bearer_auth.Middleware(token)(&hello{})

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/hello", nil)

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expect unauthorized when no token")
	}

	w = httptest.NewRecorder()
	r, _ = http.NewRequest(http.MethodGet, "/hello", nil)
	r.Header.Add("Authorization", bearer_auth.AppendBearer(token))

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expect ok when token: code = %d", w.Code)
	}
}

func TestMiddlewareWithJSON(t *testing.T) {
	token := "MY_TOKEN"
	e := ErrorResponse{Code: "unauthorized"}
	j, _ := json.Marshal(e)
	h := bearer_auth.MiddlewareJSONError(token, j)(&hello{})

	w := httptest.NewRecorder()
	r, _ := http.NewRequest(http.MethodGet, "/hello", nil)

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expect unauthorized when no token")
	}
	contentType := w.Header().Get("Content-Type")
	expect := "application/json"
	if contentType != expect {
		t.Errorf("Content-Type should be %s but %s", expect, contentType)
	}

	var res ErrorResponse
	dec := json.NewDecoder(w.Body)
	if err := dec.Decode(&res); err != nil {
		t.Fatal(err)
	}

	if res.Code != e.Code {
		t.Errorf("Bad error response")
	}
}
