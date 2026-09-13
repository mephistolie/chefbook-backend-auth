package logging

import (
	"context"
	"errors"
	"testing"
)

type testSQLStateError struct {
	message string
	state   string
}

func (e testSQLStateError) Error() string {
	return e.message
}

func (e testSQLStateError) SQLState() string {
	return e.state
}

func TestSafeErrorType(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		fallback string
		want     string
	}{
		{
			name:     "sql state excludes sensitive detail",
			err:      testSQLStateError{message: "duplicate email person@example.com", state: "23505"},
			fallback: "postgres_error",
			want:     "postgres_sqlstate_23505",
		},
		{
			name:     "canceled context",
			err:      context.Canceled,
			fallback: "postgres_error",
			want:     "context_canceled",
		},
		{
			name:     "deadline exceeded",
			err:      context.DeadlineExceeded,
			fallback: "postgres_error",
			want:     "context_deadline_exceeded",
		},
		{
			name:     "unknown error",
			err:      errors.New("token=secret-value"),
			fallback: "provider_error",
			want:     "provider_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeErrorType(tt.err, tt.fallback); got != tt.want {
				t.Fatalf("safeErrorType() = %q, want %q", got, tt.want)
			}
		})
	}
}
