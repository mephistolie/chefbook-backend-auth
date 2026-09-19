package authentication

import (
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestActivationAttemptsSurviveSetupReplacement(t *testing.T) {
	var limiter activationLimiter
	id := uuid.New()
	now := time.Now()
	for i := 0; i < 10; i++ {
		if !limiter.allow(id, now) {
			t.Fatal("too early")
		}
	}
	if limiter.allow(id, now.Add(time.Minute)) {
		t.Fatal("budget reset before window")
	}
	if !limiter.allow(uuid.New(), now) {
		t.Fatal("another account affected")
	}
	if !limiter.allow(id, now.Add(5*time.Minute)) {
		t.Fatal("window did not expire")
	}
}
