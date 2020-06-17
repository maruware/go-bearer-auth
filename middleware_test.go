package bearer_auth_test

import (
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
