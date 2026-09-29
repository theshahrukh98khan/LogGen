package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/auth"
)

// sessionCookie is the name of the cookie carrying a signed session.
const sessionCookie = "loggen_session"

// sessionTTL is how long a sign-in lasts. Long enough to get through a day of
// rule writing without re-entering a password, short enough that a forgotten
// tab on a shared machine does not stay open indefinitely.
const sessionTTL = 12 * time.Hour

// resetTTL bounds a password reset link.
const resetTTL = 30 * time.Minute

// authed reports whether a request carries a live session.
func (s *Server) authed(r *http.Request) bool {
	if s.auth == nil {
		return true // no credential store wired in, as in unit tests
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	return s.auth.Config().ValidSession(c.Value)
}

// requireAuth gates everything that reads or changes configuration, or puts
// records on the wire.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authed(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "sign in to continue",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// setSession issues the cookie.
//
// Secure is deliberately not set. The console is served over plain HTTP, and a
// Secure cookie would never be stored, locking everybody out. That is the
// honest trade for a tool with no TLS, and the README says so rather than
// implying the session is protected in transit.
func (s *Server) setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func (s *Server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// ---------------------------------------------------------------------------
// Public endpoints
// ---------------------------------------------------------------------------

// handleAuthState tells the console whether to show the app or the sign-in
// page. It is reachable without a session, so it says as little as possible to
// somebody who does not have one.
func (s *Server) handleAuthState(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
		return
	}
	cfg := s.auth.Config()
	signedIn := s.authed(r)

	out := map[string]any{
		"authenticated": signedIn,
		// Whether a reset can be sent decides if the console offers the link,
		// so it has to be public. It reveals only that a mail server is
		// configured, never the address.
		"canReset": cfg.Email != "" && cfg.SMTP.Configured(),
		"pristine": cfg.Pristine,
	}
	if d := s.throttle.LockedFor(); d > 0 {
		out["lockedFor"] = int(d.Seconds())
	}
	if signedIn {
		out["user"] = cfg.User
		out["recoveryEmail"] = cfg.Email
		out["smtp"] = redactSMTP(cfg.SMTP)
	}
	writeJSON(w, http.StatusOK, out)
}

// redactSMTP returns the mail settings without the password, which never needs
// to travel back to the browser.
func redactSMTP(s auth.SMTP) map[string]any {
	return map[string]any{
		"host": s.Host, "port": s.Port, "user": s.User, "from": s.From,
		"hasPassword": s.Password != "",
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeMsg(w, http.StatusBadRequest, "that request could not be read")
		return
	}

	if d := s.throttle.LockedFor(); d > 0 {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":     fmt.Sprintf("Too many attempts. Try again in %s.", roundMinutes(d)),
			"lockedFor": int(d.Seconds()),
		})
		return
	}

	cfg := s.auth.Config()
	// Both halves are checked before answering, and the answer never says
	// which was wrong, so this cannot be used to discover the username.
	ok := strings.EqualFold(strings.TrimSpace(in.User), cfg.User) && cfg.Verify(in.Password)
	if !ok {
		locked := s.throttle.Fail()
		out := map[string]any{"error": "That username and password do not match."}
		status := http.StatusUnauthorized
		if locked > 0 {
			// The attempt that trips the lock answers the same way as every
			// attempt after it. Returning 401 here and 429 from then on would
			// describe one state two different ways.
			out["error"] = fmt.Sprintf("Too many attempts. Try again in %s.", roundMinutes(locked))
			out["lockedFor"] = int(locked.Seconds())
			status = http.StatusTooManyRequests
		} else if left := s.throttle.Remaining(); left <= 2 {
			out["remaining"] = left
		}
		writeJSON(w, status, out)
		return
	}

	s.throttle.Succeed()
	tok, err := cfg.SessionToken(sessionTTL)
	if err != nil {
		writeMsg(w, http.StatusInternalServerError, "could not start a session")
		return
	}
	s.setSession(w, tok)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "user": cfg.User, "pristine": cfg.Pristine,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleForgot mails a reset link.
//
// The reply is identical whether or not the name matched, so this cannot be
// used to find out what the account is called.
func (s *Server) handleForgot(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User string `json:"user"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)

	same := map[string]any{
		"ok": true,
		"note": "If that account has a recovery address, a reset link is on its way. " +
			"It is good for 30 minutes.",
	}

	cfg := s.auth.Config()
	if !strings.EqualFold(strings.TrimSpace(in.User), cfg.User) ||
		cfg.Email == "" || !cfg.SMTP.Configured() {
		writeJSON(w, http.StatusOK, same)
		return
	}

	tok, err := cfg.ResetToken(resetTTL)
	if err != nil {
		writeJSON(w, http.StatusOK, same)
		return
	}
	link := fmt.Sprintf("http://%s/?reset=%s", r.Host, tok)
	if err := auth.SendReset(cfg.SMTP, cfg.Email, link); err != nil {
		// Logged rather than returned, so a mail server that is down does not
		// become a way to probe for valid usernames.
		log.Printf("password reset mail failed: %v", err)
	}
	writeJSON(w, http.StatusOK, same)
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeMsg(w, http.StatusBadRequest, "that request could not be read")
		return
	}
	if err := checkPassword(in.Password); err != nil {
		writeMsg(w, http.StatusBadRequest, err.Error())
		return
	}

	cfg := s.auth.Config()
	err := cfg.CheckReset(in.Token)
	switch {
	case err == auth.ErrExpiredToken:
		writeMsg(w, http.StatusBadRequest, "That link has expired. Ask for a new one.")
		return
	case err != nil:
		writeMsg(w, http.StatusBadRequest, "That link is not valid. Ask for a new one.")
		return
	}

	if err := s.auth.SetPassword(in.Password); err != nil {
		writeMsg(w, http.StatusInternalServerError, "could not save the new password")
		return
	}
	s.throttle.Succeed()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------------------
// Signed-in endpoints
// ---------------------------------------------------------------------------

// handleChangeAuth updates the username, the password, or both. The current
// password is always required, so a session left open on an unlocked screen
// cannot be turned into a permanent takeover.
func (s *Server) handleChangeAuth(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current  string `json:"current"`
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeMsg(w, http.StatusBadRequest, "that request could not be read")
		return
	}

	cfg := s.auth.Config()
	if !cfg.Verify(in.Current) {
		writeMsg(w, http.StatusForbidden, "That is not the current password.")
		return
	}

	name := strings.TrimSpace(in.User)
	if name != "" && name != cfg.User {
		if err := checkUser(name); err != nil {
			writeMsg(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.auth.SetUser(name); err != nil {
			writeMsg(w, http.StatusInternalServerError, "could not save the username")
			return
		}
	}
	if in.Password != "" {
		if err := checkPassword(in.Password); err != nil {
			writeMsg(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.auth.SetPassword(in.Password); err != nil {
			writeMsg(w, http.StatusInternalServerError, "could not save the password")
			return
		}
	}

	// Both changes raise the generation, which voids every session including
	// this one, so a fresh cookie is issued rather than silently signing the
	// operator out of the page they are standing on.
	cfg = s.auth.Config()
	tok, err := cfg.SessionToken(sessionTTL)
	if err != nil {
		writeMsg(w, http.StatusInternalServerError, "could not refresh the session")
		return
	}
	s.setSession(w, tok)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": cfg.User})
}

func (s *Server) handleSetRecovery(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
		SMTP  struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			User     string `json:"user"`
			Password string `json:"password"`
			From     string `json:"from"`
		} `json:"smtp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeMsg(w, http.StatusBadRequest, "that request could not be read")
		return
	}

	email := strings.TrimSpace(in.Email)
	if email != "" && !strings.Contains(email, "@") {
		writeMsg(w, http.StatusBadRequest, "that does not look like an email address")
		return
	}

	cfg := s.auth.Config()
	next := auth.SMTP{
		Host: strings.TrimSpace(in.SMTP.Host), Port: in.SMTP.Port,
		User: strings.TrimSpace(in.SMTP.User), From: strings.TrimSpace(in.SMTP.From),
		Password: in.SMTP.Password,
	}
	// A blank password means leave it alone, so saving the form without
	// retyping it does not wipe the stored one.
	if next.Password == "" {
		next.Password = cfg.SMTP.Password
	}

	if err := s.auth.SetRecovery(email, next); err != nil {
		writeMsg(w, http.StatusInternalServerError, "could not save the recovery settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"canReset": email != "" && next.Configured(),
	})
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// minPassword is short for a public service and reasonable for a lab tool on a
// private network. A longer floor that pushes people towards a sticky note is
// not an improvement.
const minPassword = 8

func checkPassword(pw string) error {
	if strings.TrimSpace(pw) == "" {
		return fmt.Errorf("a password cannot be blank")
	}
	if len([]rune(pw)) < minPassword {
		return fmt.Errorf("a password needs at least %d characters", minPassword)
	}
	return nil
}

func checkUser(name string) error {
	if len([]rune(name)) < 3 {
		return fmt.Errorf("a username needs at least 3 characters")
	}
	if strings.ContainsAny(name, " \t\r\n") {
		return fmt.Errorf("a username cannot contain spaces")
	}
	return nil
}

// writeMsg reports a sentence meant for the operator. writeErr takes an error,
// which is the right shape for a failure bubbling up from a lower layer but
// not for wording written to be read.
func writeMsg(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func roundMinutes(d time.Duration) string {
	m := int(d.Round(time.Minute).Minutes())
	if m <= 1 {
		return "a minute"
	}
	return fmt.Sprintf("%d minutes", m)
}
