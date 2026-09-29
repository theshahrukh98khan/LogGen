package auth

import (
	"sync"
	"time"
)

// Window and Lockout implement the sign-in throttle: five failures inside
// Window locks the account for Lockout.
const (
	MaxAttempts = 5
	Window      = time.Minute
	Lockout     = 10 * time.Minute
)

// Throttle counts recent failed sign-ins and locks the account when there are
// too many too quickly.
//
// It is held in memory and therefore cleared by a restart. That is a real
// limit and worth being honest about: somebody who can restart the process can
// clear a lockout. They are also somebody with a shell on the host, who could
// simply read the config, so the lockout is not what is protecting them. What
// it does protect against is an unattended console on a reachable network
// being guessed at over the wire.
type Throttle struct {
	mu       sync.Mutex
	failures []time.Time
	until    time.Time
	now      func() time.Time // swapped in tests
}

// NewThrottle builds an empty throttle.
func NewThrottle() *Throttle { return &Throttle{now: time.Now} }

func (t *Throttle) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// LockedFor returns how long the account stays locked, or zero when it is not.
func (t *Throttle) LockedFor() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lockedFor()
}

func (t *Throttle) lockedFor() time.Duration {
	if d := t.until.Sub(t.clock()); d > 0 {
		return d
	}
	return 0
}

// Fail records a rejected attempt and reports the lockout it caused, if any.
func (t *Throttle) Fail() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	if d := t.lockedFor(); d > 0 {
		return d
	}

	now := t.clock()
	// Keep only what falls inside the window, so attempts spread thinly over a
	// long period never accumulate into a lock.
	kept := t.failures[:0]
	for _, at := range t.failures {
		if now.Sub(at) < Window {
			kept = append(kept, at)
		}
	}
	t.failures = append(kept, now)

	if len(t.failures) >= MaxAttempts {
		t.until = now.Add(Lockout)
		t.failures = nil
		return Lockout
	}
	return 0
}

// Remaining reports how many attempts are left before a lock, so the console
// can warn before it happens rather than after.
func (t *Throttle) Remaining() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.clock()
	n := 0
	for _, at := range t.failures {
		if now.Sub(at) < Window {
			n++
		}
	}
	if left := MaxAttempts - n; left > 0 {
		return left
	}
	return 0
}

// Succeed clears the record after a correct password.
func (t *Throttle) Succeed() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures = nil
	t.until = time.Time{}
}
