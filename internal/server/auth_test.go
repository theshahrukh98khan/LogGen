package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/theshahrukh98khan/LogGen/internal/auth"
	"github.com/theshahrukh98khan/LogGen/internal/store"
)

func gatedServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	st, err := store.Open(filepath.Join(dir, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	creds, err := auth.Open(filepath.Join(dir, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	web := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<!doctype html>")}}
	return New(st, web, creds)
}

func do(t *testing.T, h http.Handler, method, path, body, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// signIn returns the session cookie for the default account.
func signIn(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := do(t, h, http.MethodPost, "/api/auth/login",
		`{"user":"admin","password":"admin"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("sign-in failed: %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c.Value
		}
	}
	t.Fatal("sign-in returned no session cookie")
	return ""
}

// TestEveryAPIIsGated is the security boundary of this whole feature. A
// destination names the SIEM and a send puts records on it, so nothing here
// may answer a caller without a session.
func TestEveryAPIIsGated(t *testing.T) {
	h := gatedServer(t).Handler()

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/state"},
		{http.MethodGet, "/api/controls"},
		{http.MethodGet, "/api/activity"},
		{http.MethodGet, "/api/profiles"},
		{http.MethodGet, "/api/customs"},
		{http.MethodGet, "/api/sources"},
		{http.MethodGet, "/api/placeholders"},
		{http.MethodPut, "/api/env"},
		{http.MethodPost, "/api/profiles"},
		{http.MethodPost, "/api/send"},
		{http.MethodPost, "/api/preview"},
		{http.MethodPost, "/api/customs"},
		{http.MethodPost, "/api/auth/change"},
		{http.MethodPut, "/api/auth/recovery"},
	} {
		rec := do(t, h, c.method, c.path, "{}", "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d without a session, want 401",
				c.method, c.path, rec.Code)
		}
	}
}

// The sign-in endpoints have to answer without a session, or there is no way
// to get one.
func TestAuthEndpointsAreReachable(t *testing.T) {
	h := gatedServer(t).Handler()
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/auth/state", ""},
		{http.MethodPost, "/api/auth/login", `{"user":"admin","password":"wrong"}`},
		{http.MethodPost, "/api/auth/logout", ""},
		{http.MethodPost, "/api/auth/forgot", `{"user":"admin"}`},
		{http.MethodPost, "/api/auth/reset", `{"token":"x","password":"longenough"}`},
	} {
		rec := do(t, h, c.method, c.path, c.body, "")
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s %s is not routed", c.method, c.path)
		}
	}
}

func TestSignInThenUseTheAPI(t *testing.T) {
	h := gatedServer(t).Handler()
	cookie := signIn(t, h)

	if rec := do(t, h, http.MethodGet, "/api/state", "", cookie); rec.Code != http.StatusOK {
		t.Fatalf("GET /api/state with a session = %d, want 200", rec.Code)
	}
	// A forged cookie must not work.
	if rec := do(t, h, http.MethodGet, "/api/state", "", cookie+"x"); rec.Code != http.StatusUnauthorized {
		t.Errorf("a tampered cookie was accepted: %d", rec.Code)
	}
}

func TestSessionCookieIsHttpOnly(t *testing.T) {
	h := gatedServer(t).Handler()
	rec := do(t, h, http.MethodPost, "/api/auth/login", `{"user":"admin","password":"admin"}`, "")
	for _, c := range rec.Result().Cookies() {
		if c.Name != sessionCookie {
			continue
		}
		if !c.HttpOnly {
			t.Error("the session cookie is readable from script")
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Error("the session cookie has no SameSite protection")
		}
		return
	}
	t.Fatal("no session cookie was issued")
}

// A wrong username and a wrong password must be indistinguishable, or the
// endpoint becomes a way to discover the account name.
func TestLoginDoesNotRevealWhichHalfWasWrong(t *testing.T) {
	h := gatedServer(t).Handler()

	msg := func(body string) string {
		rec := do(t, h, http.MethodPost, "/api/auth/login", body, "")
		var out struct{ Error string }
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Error
	}
	badUser := msg(`{"user":"someone-else","password":"admin"}`)
	badPass := msg(`{"user":"admin","password":"not-it"}`)
	if badUser != badPass {
		t.Errorf("a bad username says %q but a bad password says %q", badUser, badPass)
	}
}

func TestLockoutAfterFiveFailures(t *testing.T) {
	h := gatedServer(t).Handler()

	for i := 1; i <= auth.MaxAttempts-1; i++ {
		rec := do(t, h, http.MethodPost, "/api/auth/login", `{"user":"admin","password":"no"}`, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401", i, rec.Code)
		}
	}
	rec := do(t, h, http.MethodPost, "/api/auth/login", `{"user":"admin","password":"no"}`, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the fifth failure = %d, want 429", rec.Code)
	}

	// The correct password must not get in while the account is locked, or
	// the lockout protects nothing.
	rec = do(t, h, http.MethodPost, "/api/auth/login", `{"user":"admin","password":"admin"}`, "")
	if rec.Code == http.StatusOK {
		t.Error("the right password signed in during a lockout")
	}
}

func TestChangeRequiresTheCurrentPassword(t *testing.T) {
	h := gatedServer(t).Handler()
	cookie := signIn(t, h)

	rec := do(t, h, http.MethodPost, "/api/auth/change",
		`{"current":"not-the-password","password":"a-long-new-one"}`, cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("change with a wrong current password = %d, want 403", rec.Code)
	}
	// The old password must still work, which proves nothing was written.
	if rec := do(t, h, http.MethodPost, "/api/auth/login",
		`{"user":"admin","password":"admin"}`, ""); rec.Code != http.StatusOK {
		t.Error("the password changed despite a wrong current one")
	}
}

func TestShortPasswordsAreRefused(t *testing.T) {
	h := gatedServer(t).Handler()
	cookie := signIn(t, h)

	rec := do(t, h, http.MethodPost, "/api/auth/change",
		`{"current":"admin","password":"short"}`, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a five character password was accepted: %d", rec.Code)
	}
}

// The mail password is write-only as far as the browser is concerned.
func TestRecoveryNeverReturnsTheMailPassword(t *testing.T) {
	h := gatedServer(t).Handler()
	cookie := signIn(t, h)

	rec := do(t, h, http.MethodPut, "/api/auth/recovery",
		`{"email":"soc@example.com","smtp":{"host":"smtp.example.com","port":587,"from":"lg@example.com","user":"u","password":"super-secret"}}`,
		cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("saving recovery = %d: %s", rec.Code, rec.Body.String())
	}

	rec = do(t, h, http.MethodGet, "/api/auth/state", "", cookie)
	if strings.Contains(rec.Body.String(), "super-secret") {
		t.Error("the mail password came back to the browser")
	}
	if !strings.Contains(rec.Body.String(), `"hasPassword":true`) {
		t.Error("the console cannot tell that a mail password is stored")
	}
}

// Saving the form without retyping the mail password must not wipe it.
func TestBlankMailPasswordKeepsTheStoredOne(t *testing.T) {
	s := gatedServer(t)
	h := s.Handler()
	cookie := signIn(t, h)

	do(t, h, http.MethodPut, "/api/auth/recovery",
		`{"email":"a@example.com","smtp":{"host":"h","port":587,"from":"f@example.com","password":"keep-me"}}`, cookie)
	do(t, h, http.MethodPut, "/api/auth/recovery",
		`{"email":"a@example.com","smtp":{"host":"h","port":587,"from":"f@example.com","password":""}}`, cookie)

	if got := s.auth.Config().SMTP.Password; got != "keep-me" {
		t.Errorf("mail password = %q after a blank save, want it kept", got)
	}
}

// A reset request must answer the same way whatever name is given.
func TestForgotDoesNotRevealTheUsername(t *testing.T) {
	h := gatedServer(t).Handler()

	a := do(t, h, http.MethodPost, "/api/auth/forgot", `{"user":"admin"}`, "")
	b := do(t, h, http.MethodPost, "/api/auth/forgot", `{"user":"nobody"}`, "")
	if a.Code != b.Code || a.Body.String() != b.Body.String() {
		t.Errorf("a known and an unknown username differ:\n  %d %s\n  %d %s",
			a.Code, a.Body.String(), b.Code, b.Body.String())
	}
}
