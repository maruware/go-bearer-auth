package bearer_auth

import (
	"net/http"
	"strings"
)

func validateToken(validToken string, r *http.Request) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, BEARER_PREFIX) {
		return false
	}
	t := strings.TrimPrefix(h, BEARER_PREFIX)
	if t != validToken {
		return false
	}
	return true
}

func Middleware(validToken string) func(next http.Handler) http.Handler {
	return MiddlewareWithText(validToken, "Unauthorized")
}

func MiddlewareWithText(validToken string, text string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := validateToken(validToken, r)
			if !v {
				http.Error(w, text, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func MiddlewareWithJSON(validToken string, json string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := validateToken(validToken, r)
			if !v {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, json, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
