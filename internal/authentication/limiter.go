package authentication

import (
	"github.com/google/uuid"
	"sync"
	"time"
)

type attemptWindow struct {
	start time.Time
	count int
}

// activationLimiter is a bounded single-instance safeguard, not a distributed
// abuse system. Multi-replica public deployments need a shared edge limiter.
type activationLimiter struct {
	mu      sync.Mutex
	windows map[uuid.UUID]attemptWindow
}

func (l *activationLimiter) allow(id uuid.UUID, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windows == nil {
		l.windows = map[uuid.UUID]attemptWindow{}
	}
	if len(l.windows) >= 10000 {
		for k, w := range l.windows {
			if now.Sub(w.start) >= 5*time.Minute {
				delete(l.windows, k)
			}
		}
	}
	w, ok := l.windows[id]
	if !ok && len(l.windows) >= 10000 {
		return false
	}
	if !ok || now.Sub(w.start) >= 5*time.Minute {
		w = attemptWindow{start: now}
	}
	if w.count >= 10 {
		return false
	}
	w.count++
	l.windows[id] = w
	return true
}
