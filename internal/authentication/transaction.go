package authentication

import (
	"context"
	"database/sql"
	"errors"
)

// All state transitions share a PostgreSQL transaction-scoped advisory lock.
// This initial low-volume implementation favors unambiguous revocation ordering
// over concurrent throughput. Network provider verification MUST run outside it.
// The database lock works across replicas and is released on rollback/crash.
func (e *Engine) begin(ctx context.Context) (*sql.Tx, error) {
	tx, err := e.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		tx.Rollback()
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1128808770)`); err != nil {
		tx.Rollback()
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "55P03" {
			return nil, ErrUnavailable
		}
		return nil, err
	}
	return tx, nil
}
