// Package schema installs a new auth database, never converts or wipes an existing one.
package schema

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
)

//go:embed initial.sql
var Initial string

func Initialize(ctx context.Context, db *sql.DB) error {
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1128808771)`); e != nil {
		return e
	}
	var n int
	if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_tables WHERE schemaname=current_schema()`).Scan(&n); e != nil {
		return e
	}
	if n != 0 {
		return errors.New("initial schema requires an empty database schema; no existing tables were modified")
	}
	if _, e = tx.ExecContext(ctx, Initial); e != nil {
		return e
	}
	return tx.Commit()
}
func Check(ctx context.Context, db *sql.DB) error {
	// Parse the expected columns, not just a marker that an old migration can share.
	rows, e := db.QueryContext(ctx, `SELECT a.account_id,s.refresh_token_hash,f.flow_token_hash,o.creation_timestamp,g.nonce_hash,st.type,r.password_hash
 FROM accounts a LEFT JOIN sessions s ON false LEFT JOIN authentications f ON false
 LEFT JOIN outbox o ON false LEFT JOIN google_authentication_steps g ON false
 LEFT JOIN authentication_steps st ON false LEFT JOIN registrations r ON false WHERE false`)
	if e != nil {
		return errors.New("new auth initial schema is required; apply schema/initial.sql to an explicitly selected empty database")
	}
	return rows.Close()
}
