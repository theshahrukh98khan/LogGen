// Package store persists the SIEM profiles and the simulated estate to a JSON
// file on disk, with atomic writes so a crash mid-save cannot corrupt it.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// ErrNotFound is returned when a profile ID does not exist.
var ErrNotFound = errors.New("profile not found")

type state struct {
	Env      core.Env             `json:"env"`
	Profiles []core.Profile       `json:"profiles"`
	Customs  []core.CustomControl `json:"customs,omitempty"`
}

// Store is the on-disk configuration, guarded by a mutex.
type Store struct {
	mu   sync.RWMutex
	path string
	st   state
}

// Open loads the store from path, creating it with sane defaults if missing.
//
// A file that will not parse is moved aside rather than treated as fatal. The
// alternative is a tool that refuses to start and leaves the operator to find
// and delete the file themselves, which is a poor trade for a lab tool whose
// configuration is a handful of destinations.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, s.reset()
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if err := json.Unmarshal(b, &s.st); err != nil {
		kept, moveErr := s.quarantine()
		if moveErr != nil {
			return nil, fmt.Errorf("parse %s: %w (and it could not be moved aside: %v)",
				path, err, moveErr)
		}
		log.Printf("%s could not be read (%v); it has been kept as %s and a fresh one started",
			path, err, filepath.Base(kept))
		s.st = state{}
		return s, s.reset()
	}
	s.st.Env = s.st.Env.Normalize()
	for i := range s.st.Profiles {
		s.st.Profiles[i] = s.st.Profiles[i].Normalize()
	}
	for i := range s.st.Customs {
		s.st.Customs[i] = s.st.Customs[i].Normalize()
	}
	if len(s.st.Profiles) == 0 {
		s.st.Profiles = []core.Profile{core.DefaultProfile()}
	}
	s.ensureDefault()
	return s, nil
}

// reset installs the default configuration and writes it.
func (s *Store) reset() error {
	s.st = state{Env: core.DefaultEnv(), Profiles: []core.Profile{core.DefaultProfile()}}
	return s.save()
}

// quarantine renames an unreadable config out of the way and returns where it
// went, so nothing the operator wrote is ever silently destroyed.
func (s *Store) quarantine() (string, error) {
	kept := fmt.Sprintf("%s.unreadable-%s", s.path, time.Now().Format("20060102-150405"))
	if err := os.Rename(s.path, kept); err != nil {
		return "", err
	}
	return kept, nil
}

// save writes the state atomically. Callers must hold the write lock.
func (s *Store) save() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

// ensureDefault guarantees exactly one profile carries the default flag.
// Callers must hold the write lock.
func (s *Store) ensureDefault() {
	seen := false
	for i := range s.st.Profiles {
		if s.st.Profiles[i].IsDefault && !seen {
			seen = true
			continue
		}
		s.st.Profiles[i].IsDefault = false
	}
	if !seen && len(s.st.Profiles) > 0 {
		s.st.Profiles[0].IsDefault = true
	}
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

// Env returns the simulated estate.
func (s *Store) Env() core.Env {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st.Env
}

// SetEnv replaces the simulated estate.
func (s *Store) SetEnv(e core.Env) (core.Env, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Env = e.Normalize()
	if err := s.save(); err != nil {
		return s.st.Env, err
	}
	return s.st.Env, nil
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

// Profiles returns a copy of every configured target.
func (s *Store) Profiles() []core.Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]core.Profile, len(s.st.Profiles))
	copy(out, s.st.Profiles)
	return out
}

// Profile looks up one target by ID.
func (s *Store) Profile(id string) (core.Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.st.Profiles {
		if p.ID == id {
			return p, nil
		}
	}
	return core.Profile{}, ErrNotFound
}

// Default returns the profile marked as default, falling back to the first.
func (s *Store) Default() (core.Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.st.Profiles {
		if p.IsDefault {
			return p, nil
		}
	}
	if len(s.st.Profiles) > 0 {
		return s.st.Profiles[0], nil
	}
	return core.Profile{}, ErrNotFound
}

// Resolve returns the named profile, or the default when id is empty.
func (s *Store) Resolve(id string) (core.Profile, error) {
	if strings.TrimSpace(id) == "" {
		return s.Default()
	}
	return s.Profile(id)
}

// Create adds a new target, assigning an ID when one is not supplied.
func (s *Store) Create(p core.Profile) (core.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p = p.Normalize()
	if strings.TrimSpace(p.ID) == "" {
		p.ID = newID(p.Name)
	}
	for _, existing := range s.st.Profiles {
		if existing.ID == p.ID {
			p.ID = fmt.Sprintf("%s-%d", p.ID, time.Now().UnixNano()%1000)
			break
		}
	}
	s.st.Profiles = append(s.st.Profiles, p)
	if p.IsDefault {
		s.clearDefaultsExcept(p.ID)
	}
	s.ensureDefault()
	if err := s.save(); err != nil {
		return p, err
	}
	return p, nil
}

// Update replaces an existing target in place.
func (s *Store) Update(id string, p core.Profile) (core.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := -1
	for i := range s.st.Profiles {
		if s.st.Profiles[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return core.Profile{}, ErrNotFound
	}

	p.ID = id
	p = p.Normalize()
	s.st.Profiles[idx] = p
	if p.IsDefault {
		s.clearDefaultsExcept(id)
	}
	s.ensureDefault()
	if err := s.save(); err != nil {
		return p, err
	}
	return p, nil
}

// Delete removes a target. The last remaining profile cannot be deleted.
//
// Existence is checked before the last-profile guard, so deleting an ID that
// does not exist reports that, rather than blaming the profile count.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.hasProfile(id) {
		return ErrNotFound
	}
	if len(s.st.Profiles) <= 1 {
		return errors.New("cannot delete the only profile")
	}
	idx := -1
	for i := range s.st.Profiles {
		if s.st.Profiles[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrNotFound
	}
	s.st.Profiles = append(s.st.Profiles[:idx], s.st.Profiles[idx+1:]...)
	s.ensureDefault()
	return s.save()
}

// SetDefault marks one target as the default send destination.
func (s *Store) SetDefault(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.hasProfile(id) {
		return ErrNotFound
	}
	s.clearDefaultsExcept(id)
	return s.save()
}

// hasProfile reports whether id exists. Callers must hold the lock.
func (s *Store) hasProfile(id string) bool {
	for i := range s.st.Profiles {
		if s.st.Profiles[i].ID == id {
			return true
		}
	}
	return false
}

// clearDefaultsExcept marks only id as default. Callers must hold the lock.
func (s *Store) clearDefaultsExcept(id string) {
	for i := range s.st.Profiles {
		s.st.Profiles[i].IsDefault = s.st.Profiles[i].ID == id
	}
}

// newID turns a profile name into a URL-safe identifier.
func newID(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_' || r == '.':
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	for strings.Contains(id, "--") {
		id = strings.ReplaceAll(id, "--", "-")
	}
	if id == "" {
		id = "profile"
	}
	return fmt.Sprintf("%s-%d", id, time.Now().UnixNano()%100000)
}

// ---------------------------------------------------------------------------
// Custom controls
// ---------------------------------------------------------------------------

// ErrDuplicateID is returned when a custom control would collide with an
// existing one, including a built-in.
var ErrDuplicateID = errors.New("a control with that ID already exists")

// Customs returns a copy of every operator-defined control.
func (s *Store) Customs() []core.CustomControl {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]core.CustomControl, len(s.st.Customs))
	copy(out, s.st.Customs)
	return out
}

// Custom looks up one operator-defined control.
func (s *Store) Custom(id string) (core.CustomControl, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.st.Customs {
		if c.ID == id {
			return c, nil
		}
	}
	return core.CustomControl{}, ErrNotFound
}

// CreateCustom adds a control. reserved lists IDs already taken by built-ins,
// so a custom control can never shadow one.
func (s *Store) CreateCustom(c core.CustomControl, reserved map[string]bool) (core.CustomControl, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c = c.Normalize()
	if strings.TrimSpace(c.ID) == "" {
		c.ID = core.CustomID(c.Source, c.Name)
	}
	if reserved[c.ID] {
		return c, ErrDuplicateID
	}
	for _, existing := range s.st.Customs {
		if existing.ID == c.ID {
			return c, ErrDuplicateID
		}
	}

	s.st.Customs = append(s.st.Customs, c)
	if err := s.save(); err != nil {
		return c, err
	}
	return c, nil
}

// UpdateCustom replaces a control in place.
func (s *Store) UpdateCustom(id string, c core.CustomControl) (core.CustomControl, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := -1
	for i := range s.st.Customs {
		if s.st.Customs[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return core.CustomControl{}, ErrNotFound
	}

	c.ID = id
	c = c.Normalize()
	s.st.Customs[idx] = c
	if err := s.save(); err != nil {
		return c, err
	}
	return c, nil
}

// DeleteCustom removes a control.
func (s *Store) DeleteCustom(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.st.Customs {
		if s.st.Customs[i].ID == id {
			s.st.Customs = append(s.st.Customs[:i], s.st.Customs[i+1:]...)
			return s.save()
		}
	}
	return ErrNotFound
}
