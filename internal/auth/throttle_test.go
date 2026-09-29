package auth

import (
	"testing"
	"time"
)

// clocked builds a throttle whose time the test drives, so a ten minute
// lockout can be verified without a ten minute test.
func clocked() (*Throttle, *time.Time) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	t := &Throttle{now: func() time.Time { return now }}
	return t, &now
}

func TestFiveFailuresInAMinuteLocks(t *testing.T) {
	th, now := clocked()

	for i := 1; i < MaxAttempts; i++ {
		if d := th.Fail(); d != 0 {
			t.Fatalf("locked after %d failures, want %d", i, MaxAttempts)
		}
		*now = now.Add(5 * time.Second)
	}
	if d := th.Fail(); d != Lockout {
		t.Fatalf("fifth failure returned %v, want %v", d, Lockout)
	}
	if th.LockedFor() != Lockout {
		t.Errorf("LockedFor = %v, want %v", th.LockedFor(), Lockout)
	}
}

// Attempts spread thinly must never accumulate into a lock, or somebody who
// mistypes once a day is eventually locked out for it.
func TestFailuresOutsideTheWindowDoNotAccumulate(t *testing.T) {
	th, now := clocked()
	for i := 0; i < MaxAttempts*3; i++ {
		if d := th.Fail(); d != 0 {
			t.Fatalf("locked on attempt %d despite being spread out", i+1)
		}
		*now = now.Add(Window + time.Second)
	}
}

func TestLockExpires(t *testing.T) {
	th, now := clocked()
	for i := 0; i < MaxAttempts; i++ {
		th.Fail()
	}
	if th.LockedFor() == 0 {
		t.Fatal("not locked after the threshold")
	}

	*now = now.Add(Lockout - time.Second)
	if th.LockedFor() == 0 {
		t.Error("the lock lifted early")
	}
	*now = now.Add(2 * time.Second)
	if d := th.LockedFor(); d != 0 {
		t.Errorf("still locked %v after the lockout elapsed", d)
	}
}

// While locked, further attempts must not extend the lock indefinitely. A
// scanner hammering the endpoint would otherwise keep a legitimate operator
// out for as long as it kept trying.
func TestAttemptsDuringLockDoNotExtendIt(t *testing.T) {
	th, now := clocked()
	for i := 0; i < MaxAttempts; i++ {
		th.Fail()
	}
	end := th.LockedFor()

	*now = now.Add(time.Minute)
	th.Fail()
	th.Fail()

	want := end - time.Minute
	if got := th.LockedFor(); got != want {
		t.Errorf("LockedFor = %v, want %v: attempts during a lock extended it", got, want)
	}
}

func TestSuccessClearsTheCount(t *testing.T) {
	th, now := clocked()
	for i := 0; i < MaxAttempts-1; i++ {
		th.Fail()
		*now = now.Add(time.Second)
	}
	th.Succeed()

	if th.Remaining() != MaxAttempts {
		t.Errorf("Remaining = %d after success, want %d", th.Remaining(), MaxAttempts)
	}
	if d := th.Fail(); d != 0 {
		t.Error("locked immediately after a successful sign-in reset the count")
	}
}

func TestRemainingCountsDown(t *testing.T) {
	th, _ := clocked()
	if got := th.Remaining(); got != MaxAttempts {
		t.Fatalf("Remaining = %d on a fresh throttle, want %d", got, MaxAttempts)
	}
	th.Fail()
	if got := th.Remaining(); got != MaxAttempts-1 {
		t.Errorf("Remaining = %d after one failure, want %d", got, MaxAttempts-1)
	}
}
