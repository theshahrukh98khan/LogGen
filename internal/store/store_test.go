package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

func tempStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profiles.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s, path
}

func TestOpenCreatesDefaults(t *testing.T) {
	s, path := tempStore(t)

	if _, err := os.Stat(path); err != nil {
		t.Errorf("config was not written: %v", err)
	}
	if got := len(s.Profiles()); got != 1 {
		t.Errorf("profiles = %d, want 1", got)
	}
	if s.Env().Domain != core.DefaultEnv().Domain {
		t.Errorf("estate was not defaulted: %+v", s.Env())
	}
	if _, err := s.Default(); err != nil {
		t.Errorf("no default profile: %v", err)
	}
}

func TestOpenCreatesMissingDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "profiles.json")
	if _, err := Open(path); err != nil {
		t.Fatalf("Open with a missing directory: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config not created: %v", err)
	}
}

func TestReopenRoundTrips(t *testing.T) {
	s, path := tempStore(t)

	if _, err := s.Create(core.Profile{Name: "Prod", Host: "10.0.0.5", Port: 1514,
		Protocol: core.ProtoTCP}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.CreateCustom(core.CustomControl{
		Source: "paloalto", Name: "Threat", Template: "x={{user}}",
	}, nil); err != nil {
		t.Fatalf("CreateCustom: %v", err)
	}
	if _, err := s.SetEnv(core.Env{Domain: "acme.test", NetBIOS: "acme"}); err != nil {
		t.Fatalf("SetEnv: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := len(reopened.Profiles()); got != 2 {
		t.Errorf("profiles after reopen = %d, want 2", got)
	}
	if got := len(reopened.Customs()); got != 1 {
		t.Errorf("customs after reopen = %d, want 1", got)
	}
	if reopened.Env().Domain != "acme.test" {
		t.Errorf("estate after reopen = %q", reopened.Env().Domain)
	}
	if reopened.Env().NetBIOS != "ACME" {
		t.Errorf("estate was not normalised on load: %q", reopened.Env().NetBIOS)
	}
}

// A config that will not parse must be kept, not destroyed, and must not stop
// the tool from starting.
func TestOpenQuarantinesAnUnreadableConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open should recover from a bad config, got: %v", err)
	}
	if len(s.Profiles()) != 1 {
		t.Errorf("did not start from defaults: %d profiles", len(s.Profiles()))
	}

	entries, _ := os.ReadDir(dir)
	var kept string
	for _, e := range entries {
		if strings.Contains(e.Name(), "unreadable") {
			kept = e.Name()
		}
	}
	if kept == "" {
		t.Fatal("the unreadable config was not kept")
	}
	b, err := os.ReadFile(filepath.Join(dir, kept))
	if err != nil || !strings.Contains(string(b), "this is not json") {
		t.Errorf("the kept copy does not hold the original content")
	}

	// And the fresh config must be valid.
	var fresh state
	b, _ = os.ReadFile(path)
	if err := json.Unmarshal(b, &fresh); err != nil {
		t.Errorf("replacement config is not valid JSON: %v", err)
	}
}

func TestOpenRepairsAnEmptyProfileList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(path, []byte(`{"env":{},"profiles":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(s.Profiles()) != 1 {
		t.Errorf("an empty profile list was not repaired: %d", len(s.Profiles()))
	}
	if _, err := s.Default(); err != nil {
		t.Errorf("no default after repair: %v", err)
	}
}

func TestExactlyOneDefault(t *testing.T) {
	s, _ := tempStore(t)

	a, _ := s.Create(core.Profile{Name: "A", Host: "h", Port: 514, IsDefault: true})
	b, _ := s.Create(core.Profile{Name: "B", Host: "h", Port: 514, IsDefault: true})

	count := 0
	for _, p := range s.Profiles() {
		if p.IsDefault {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d profiles are marked default, want exactly 1", count)
	}
	def, _ := s.Default()
	if def.ID != b.ID {
		t.Errorf("default = %q, want the most recent (%q)", def.ID, b.ID)
	}

	if err := s.SetDefault(a.ID); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	def, _ = s.Default()
	if def.ID != a.ID {
		t.Errorf("default after SetDefault = %q, want %q", def.ID, a.ID)
	}
}

// Deleting the default must promote another, never leave the store without one.
func TestDeletingTheDefaultPromotesAnother(t *testing.T) {
	s, _ := tempStore(t)
	extra, _ := s.Create(core.Profile{Name: "Extra", Host: "h", Port: 514, IsDefault: true})

	if err := s.Delete(extra.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Default(); err != nil {
		t.Errorf("no default after deleting it: %v", err)
	}
}

func TestCannotDeleteTheLastProfile(t *testing.T) {
	s, _ := tempStore(t)
	only := s.Profiles()[0]
	if err := s.Delete(only.ID); err == nil {
		t.Error("deleting the only profile should fail")
	}
	if len(s.Profiles()) != 1 {
		t.Error("the only profile was removed anyway")
	}
}

func TestUnknownIDs(t *testing.T) {
	s, _ := tempStore(t)
	if _, err := s.Profile("nope"); err != ErrNotFound {
		t.Errorf("Profile(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := s.Update("nope", core.Profile{Name: "x"}); err != ErrNotFound {
		t.Errorf("Update(unknown) = %v, want ErrNotFound", err)
	}
	if err := s.Delete("nope"); err != ErrNotFound {
		t.Errorf("Delete(unknown) = %v, want ErrNotFound", err)
	}
	if err := s.SetDefault("nope"); err != ErrNotFound {
		t.Errorf("SetDefault(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := s.Custom("nope"); err != ErrNotFound {
		t.Errorf("Custom(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := s.UpdateCustom("nope", core.CustomControl{}); err != ErrNotFound {
		t.Errorf("UpdateCustom(unknown) = %v, want ErrNotFound", err)
	}
	if err := s.DeleteCustom("nope"); err != ErrNotFound {
		t.Errorf("DeleteCustom(unknown) = %v, want ErrNotFound", err)
	}
}

func TestResolveFallsBackToTheDefault(t *testing.T) {
	s, _ := tempStore(t)
	def, _ := s.Default()

	got, err := s.Resolve("")
	if err != nil || got.ID != def.ID {
		t.Errorf("Resolve(\"\") = %q/%v, want the default %q", got.ID, err, def.ID)
	}
	if got, err = s.Resolve("   "); err != nil || got.ID != def.ID {
		t.Errorf("Resolve(whitespace) did not fall back to the default")
	}
}

// A custom control must never take an ID a built-in already uses.
func TestCustomCannotShadowABuiltin(t *testing.T) {
	s, _ := tempStore(t)
	reserved := map[string]bool{"win-4625-logon-failed": true}

	_, err := s.CreateCustom(core.CustomControl{
		ID: "win-4625-logon-failed", Source: "windows", Name: "Shadow", Template: "x",
	}, reserved)
	if err != ErrDuplicateID {
		t.Errorf("shadowing a built-in = %v, want ErrDuplicateID", err)
	}
}

func TestCustomDuplicateRejected(t *testing.T) {
	s, _ := tempStore(t)
	cc := core.CustomControl{Source: "src", Name: "Same name", Template: "x"}

	if _, err := s.CreateCustom(cc, nil); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := s.CreateCustom(cc, nil); err != ErrDuplicateID {
		t.Errorf("duplicate create = %v, want ErrDuplicateID", err)
	}
	if got := len(s.Customs()); got != 1 {
		t.Errorf("customs = %d, want 1", got)
	}
}

func TestCustomUpdateKeepsID(t *testing.T) {
	s, _ := tempStore(t)
	cc, _ := s.CreateCustom(core.CustomControl{
		Source: "src", Name: "Original", Template: "x", Severity: "low",
	}, nil)

	// An update that carries a different ID must not be able to move the record.
	got, err := s.UpdateCustom(cc.ID, core.CustomControl{
		ID: "something-else", Source: "src", Name: "Renamed",
		Template: "y", Severity: "high",
	})
	if err != nil {
		t.Fatalf("UpdateCustom: %v", err)
	}
	if got.ID != cc.ID {
		t.Errorf("ID changed on update: %q -> %q", cc.ID, got.ID)
	}
	if got.Name != "Renamed" || got.Severity != "high" {
		t.Errorf("update not applied: %+v", got)
	}
	if len(s.Customs()) != 1 {
		t.Errorf("update created a second record")
	}
}

// Returned slices must be copies, or a caller could mutate the store's state.
func TestAccessorsReturnCopies(t *testing.T) {
	s, _ := tempStore(t)
	s.CreateCustom(core.CustomControl{Source: "src", Name: "C", Template: "x"}, nil)

	profiles := s.Profiles()
	profiles[0].Name = "mutated"
	if s.Profiles()[0].Name == "mutated" {
		t.Error("Profiles() exposed the store's own slice")
	}

	customs := s.Customs()
	customs[0].Name = "mutated"
	if s.Customs()[0].Name == "mutated" {
		t.Error("Customs() exposed the store's own slice")
	}
}

// The config is rewritten on every change, so concurrent writers must not be
// able to interleave and leave it unparseable.
func TestConcurrentWritesKeepTheConfigValid(t *testing.T) {
	s, path := tempStore(t)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 15; j++ {
				p, err := s.Create(core.Profile{
					Name: "p", Host: "127.0.0.1", Port: 514,
				})
				if err == nil {
					s.Delete(p.ID)
				}
				s.SetEnv(core.Env{Domain: "d.test"})
				_ = s.Profiles()
				_ = s.Customs()
			}
		}(i)
	}
	wg.Wait()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("config is corrupt after concurrent writes: %v", err)
	}
	if len(st.Profiles) == 0 {
		t.Error("all profiles were lost")
	}

	count := 0
	for _, p := range st.Profiles {
		if p.IsDefault {
			count++
		}
	}
	if count != 1 {
		t.Errorf("%d defaults after concurrent writes, want 1", count)
	}
}

// A failed write must not leave a truncated config behind.
func TestSaveIsAtomic(t *testing.T) {
	s, path := tempStore(t)
	for i := 0; i < 20; i++ {
		if _, err := s.Create(core.Profile{Name: "p", Host: "127.0.0.1", Port: 514}); err != nil {
			t.Fatal(err)
		}
	}
	// The temporary file used during a save must not survive it.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("a temporary config file was left behind")
	}
}
