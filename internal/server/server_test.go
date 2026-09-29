package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/theshahrukh98khan/LogGen/internal/core"
)

// TestRecordStampsAndReturnsSequence guards a bug that made a send response
// impossible to correlate with the activity feed: record took the entry by
// value, so it stamped the sequence on its own copy and the caller was left
// holding seq 0 while the feed showed the real number.
func TestRecordStampsAndReturnsSequence(t *testing.T) {
	s := &Server{}

	first := s.record(core.Activity{ControlID: "a"})
	if first.Seq != 1 {
		t.Errorf("first entry Seq = %d, want 1", first.Seq)
	}

	second := s.record(core.Activity{ControlID: "b"})
	if second.Seq != 2 {
		t.Errorf("second entry Seq = %d, want 2", second.Seq)
	}

	// What the caller was handed must match what the feed holds.
	feed := s.activity()
	if len(feed) != 2 {
		t.Fatalf("feed has %d entries, want 2", len(feed))
	}
	if feed[0].Seq != second.Seq || feed[1].Seq != first.Seq {
		t.Errorf("returned sequences %d/%d do not match the feed %d/%d",
			first.Seq, second.Seq, feed[1].Seq, feed[0].Seq)
	}
}

func TestActivityIsNewestFirst(t *testing.T) {
	s := &Server{}
	for i := 0; i < 5; i++ {
		s.record(core.Activity{ControlID: "x"})
	}
	feed := s.activity()
	for i := 1; i < len(feed); i++ {
		if feed[i-1].Seq <= feed[i].Seq {
			t.Fatalf("feed is not newest first: %d then %d", feed[i-1].Seq, feed[i].Seq)
		}
	}
}

// The ring buffer must drop the oldest entries, not the newest.
func TestActivityRingKeepsTheNewest(t *testing.T) {
	s := &Server{}
	for i := 0; i < activityCap+50; i++ {
		s.record(core.Activity{ControlID: "x"})
	}
	feed := s.activity()
	if len(feed) != activityCap {
		t.Fatalf("feed holds %d entries, want the cap of %d", len(feed), activityCap)
	}
	if feed[0].Seq != uint64(activityCap+50) {
		t.Errorf("newest Seq = %d, want %d", feed[0].Seq, activityCap+50)
	}
	if feed[len(feed)-1].Seq != 51 {
		t.Errorf("oldest retained Seq = %d, want 51", feed[len(feed)-1].Seq)
	}
}

// TestVersionHeader covers the header a console left open across a rebuild
// uses to notice that its markup and stylesheet came from a binary that is no
// longer running.
func TestVersionHeader(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	s := &Server{Version: "v9.9.9-test"}
	rec := httptest.NewRecorder()
	s.stamp(ok).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/activity", nil))
	if got := rec.Header().Get("X-LogGen-Version"); got != "v9.9.9-test" {
		t.Errorf("X-LogGen-Version = %q, want %q", got, "v9.9.9-test")
	}

	// An unstamped build must not send an empty header. The console treats a
	// change in this value as a rebuild, and empty to empty is not a change,
	// but sending it at all invites that comparison to go wrong.
	plain := &Server{}
	rec = httptest.NewRecorder()
	plain.stamp(ok).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/activity", nil))
	if _, sent := rec.Header()["X-Loggen-Version"]; sent {
		t.Error("an unversioned build should not send the header at all")
	}
}
