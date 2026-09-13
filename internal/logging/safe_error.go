package logging

import (
	"context"
	"errors"
)

type sqlStateError interface {
	SQLState() string
}

func safeErrorType(err error, fallback string) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "context_deadline_exceeded"
	}

	var sqlErr sqlStateError
	if errors.As(err, &sqlErr) {
		return "postgres_sqlstate_" + sqlErr.SQLState()
	}

	return fallback
}
