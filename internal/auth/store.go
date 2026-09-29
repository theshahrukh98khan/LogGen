package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Store persists the credential.
//
// It lives in its own file rather than in profiles.json, because that is the
// file somebody pastes into an issue to show their destinations, and it is
// written 0600 so it is not world readable on a shared host.
type Store struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

// Open loads the credential, creating the default admin account when there is
// none.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		cfg, err := New()
		if err != nil {
			return nil, err
		}
		s.cfg = cfg
		return s, s.save()
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if err := json.Unmarshal(b, &s.cfg); err != nil {
		// Unlike the destinations file, this one is not quarantined and
		// replaced. Silently resetting to admin/admin because a byte got
		// flipped would turn file corruption into an open door.
		return nil, fmt.Errorf("read %s: %w (move it aside to start over with the default account)", path, err)
	}
	if len(s.cfg.Secret) == 0 || len(s.cfg.Hash) == 0 || s.cfg.User == "" {
		return nil, fmt.Errorf("%s is missing its credential; move it aside to start over", path)
	}
	return s, nil
}

// Config returns a copy of the stored credential.
func (s *Store) Config() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Save replaces the credential wholesale.
func (s *Store) Save(c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = c
	return s.save()
}

// SetPassword changes the password, which also signs out every session.
func (s *Store) SetPassword(pw string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.cfg.SetPassword(pw); err != nil {
		return err
	}
	return s.save()
}

// SetUser renames the account. The session generation rises with it, so the
// rename takes effect immediately rather than leaving a live session under a
// name that no longer exists.
func (s *Store) SetUser(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.User = name
	s.cfg.Gen++
	return s.save()
}

// SetRecovery stores the address a reset link is sent to and the server it
// goes through.
func (s *Store) SetRecovery(email string, smtp SMTP) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Email = email
	s.cfg.SMTP = smtp
	return s.save()
}

// Reset returns the account to the shipped default. It is reachable only from
// the command line, which is the one place the caller has already proved they
// own the machine.
func (s *Store) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := New()
	if err != nil {
		return err
	}
	// The recovery settings are deliberately kept: somebody recovering a
	// forgotten password should not also lose their mail configuration.
	cfg.Email, cfg.SMTP = s.cfg.Email, s.cfg.SMTP
	s.cfg = cfg
	return s.save()
}

// save writes atomically. Callers must hold the write lock.
func (s *Store) save() error {
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write temp credential: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace credential: %w", err)
	}
	return nil
}
