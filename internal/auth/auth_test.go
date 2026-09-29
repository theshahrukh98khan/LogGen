package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultAccount(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if c.User != DefaultUser {
		t.Errorf("user = %q, want %q", c.User, DefaultUser)
	}
	if !c.Verify(DefaultPassword) {
		t.Error("the default password does not verify")
	}
	if c.Verify("not the password") {
		t.Error("a wrong password verified")
	}
	if !c.Pristine {
		t.Error("a fresh account should be marked as still on the default")
	}
	// The password must not be recoverable from what is stored.
	if string(c.Hash) == DefaultPassword {
		t.Fatal("the password is stored in the clear")
	}
}

func TestSetPasswordRotatesSaltAndInvalidatesSessions(t *testing.T) {
	c, _ := New()
	tok, err := c.SessionToken(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ValidSession(tok) {
		t.Fatal("a fresh session did not validate")
	}

	oldSalt := string(c.Salt)
	if err := c.SetPassword("a much better password"); err != nil {
		t.Fatal(err)
	}
	if string(c.Salt) == oldSalt {
		t.Error("the salt was reused across a password change")
	}
	if c.Pristine {
		t.Error("changing the password should clear the default marker")
	}
	if !c.Verify("a much better password") {
		t.Error("the new password does not verify")
	}
	if c.Verify(DefaultPassword) {
		t.Error("the old password still verifies")
	}
	// A session minted before the change must not survive it.
	if c.ValidSession(tok) {
		t.Error("changing the password left an old session valid")
	}
}

func TestSessionTokenRejectsTampering(t *testing.T) {
	c, _ := New()
	tok, _ := c.SessionToken(time.Hour)

	for _, bad := range []string{
		"", "junk", tok + "x", "x" + tok,
		tok[:len(tok)-2], // truncated signature
	} {
		if c.ValidSession(bad) {
			t.Errorf("accepted a bad token: %q", bad)
		}
	}

	// A token signed by a different install must not work here.
	other, _ := New()
	otherTok, _ := other.SessionToken(time.Hour)
	if c.ValidSession(otherTok) {
		t.Error("accepted a token signed with another secret")
	}
}

func TestSessionExpires(t *testing.T) {
	c, _ := New()
	tok, _ := c.SessionToken(-time.Second)
	if c.ValidSession(tok) {
		t.Error("an expired session validated")
	}
}

// A session cookie must not be usable as a password reset. Without the purpose
// check, stealing a cookie would be enough to take the account over entirely.
func TestSessionIsNotAResetToken(t *testing.T) {
	c, _ := New()
	sess, _ := c.SessionToken(time.Hour)
	if err := c.CheckReset(sess); err == nil {
		t.Error("a session token was accepted as a password reset")
	}

	reset, _ := c.ResetToken(time.Minute)
	if c.ValidSession(reset) {
		t.Error("a reset token was accepted as a session")
	}
	if err := c.CheckReset(reset); err != nil {
		t.Errorf("a valid reset token was rejected: %v", err)
	}
}

func TestResetTokenIsSingleUse(t *testing.T) {
	c, _ := New()
	tok, _ := c.ResetToken(time.Hour)
	if err := c.CheckReset(tok); err != nil {
		t.Fatalf("fresh reset token rejected: %v", err)
	}
	// Using it means setting a password, which must stop it working again.
	if err := c.SetPassword("whatever they chose"); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckReset(tok); err == nil {
		t.Error("a reset token still worked after the password was changed")
	}
}

func TestExpiredResetIsDistinguishable(t *testing.T) {
	c, _ := New()
	tok, _ := c.ResetToken(-time.Second)
	if err := c.CheckReset(tok); err != ErrExpiredToken {
		t.Errorf("err = %v, want ErrExpiredToken (so the console can offer a new link)", err)
	}
}

func TestStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Config().Verify(DefaultPassword) {
		t.Fatal("a new store does not carry the default password")
	}
	if err := s.SetPassword("second password"); err != nil {
		t.Fatal(err)
	}

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Config().Verify("second password") {
		t.Error("the changed password did not survive a reload")
	}
	if again.Config().Verify(DefaultPassword) {
		t.Error("the default password still works after a change")
	}
}

// Corruption must not fall back to admin/admin, which would turn a flipped
// byte into an open door.
func TestCorruptStoreIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	if _, err := Open(path); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(path, "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("an unreadable credential file was accepted")
	}
}

func TestSMTPConfigured(t *testing.T) {
	if (SMTP{}).Configured() {
		t.Error("an empty SMTP config reported as usable")
	}
	if (SMTP{Host: "mail.example", Port: 587}).Configured() {
		t.Error("SMTP without a From address reported as usable")
	}
	if !(SMTP{Host: "mail.example", Port: 587, From: "a@example"}).Configured() {
		t.Error("a complete SMTP config reported as unusable")
	}
}

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s), 0o600) }
