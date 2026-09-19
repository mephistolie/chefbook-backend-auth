package schema_test

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

//go:embed initial.sql
var initialSchema string

// Only explicitly supplied disposable test databases are used. The harness never
// reads application configuration or credentials and isolates objects in a fresh
// random schema, which it drops on completion.
func database(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("AUTH_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set AUTH_TEST_DATABASE_URL to a disposable PostgreSQL test database")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid AUTH_TEST_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin := stdlib.OpenDB(*cfg)
	admin.SetMaxOpenConns(1)
	name := "auth_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal("cannot create isolated test schema")
	}
	copy := cfg.Copy()
	copy.RuntimeParams["search_path"] = name
	db := stdlib.OpenDB(*copy)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		db.Close()
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("cannot remove isolated test schema")
		}
		admin.Close()
	})
	if _, err = db.ExecContext(ctx, initialSchema); err != nil {
		t.Fatalf("initial schema failed: %v", err)
	}
	return db
}
func execute(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, q, args...); err != nil {
		t.Fatal(err)
	}
}
func rejected(t *testing.T, db *sql.DB, state, q string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, q, args...)
	var classified interface{ SQLState() string }
	if err == nil || !errors.As(err, &classified) || classified.SQLState() != state {
		t.Fatalf("wanted SQLSTATE %s, got %v", state, err)
	}
}
func TestInitialSchemaConstraints(t *testing.T) {
	db := database(t)
	account := uuid.New()
	other := uuid.New()
	execute(t, db, `INSERT INTO accounts(account_id,email) VALUES($1,'one@example.test'),($2,'two@example.test')`, account, other)
	var session int64
	if err := db.QueryRow(`INSERT INTO sessions(account_id,refresh_token_hash,ip,user_agent,expiration_timestamp) VALUES($1,'\x01','127.0.0.1','test',now()+interval '1 hour') RETURNING session_id`, account).Scan(&session); err != nil {
		t.Fatal(err)
	}
	t.Run("unique provider subject", func(t *testing.T) {
		execute(t, db, `INSERT INTO identities(account_id,provider,subject) VALUES($1,'google','123'),($1,'vk','123')`, account)
		rejected(t, db, "23505", `INSERT INTO identities(account_id,provider,subject) VALUES($1,'google','123')`, other)
	})
	t.Run("sensitive authentication requires session", func(t *testing.T) {
		rejected(t, db, "23514", `INSERT INTO authentications(authentication_id,purpose,flow_token_hash,expiration_timestamp) VALUES($1,'passwordChange','\x02',now())`, uuid.New())
	})
	t.Run("grant hash and expiry paired", func(t *testing.T) {
		rejected(t, db, "23514", `INSERT INTO authentications(authentication_id,purpose,flow_token_hash,expiration_timestamp,confirmation_token_hash) VALUES($1,'signIn','\x03',now(),'\x04')`, uuid.New())
	})
	t.Run("completion requires account and timestamp", func(t *testing.T) {
		rejected(t, db, "23514", `INSERT INTO authentications(authentication_id,purpose,status,flow_token_hash,expiration_timestamp) VALUES($1,'signIn','completed','\x05',now())`, uuid.New())
	})
	auth := uuid.New()
	challenge := uuid.New()
	execute(t, db, `INSERT INTO authentications(authentication_id,purpose,flow_token_hash,expiration_timestamp) VALUES($1,'signUp','\x06',now()+interval '1 hour')`, auth)
	execute(t, db, `INSERT INTO authentication_steps(step_id,authentication_id,type,expiration_timestamp) VALUES($1,$2,'googleVerification',now()+interval '1 hour')`, challenge, auth)
	t.Run("oauth exactly one binding", func(t *testing.T) {
		q := `INSERT INTO oauth_requests(state_hash,provider,step_id,session_id,client_binding_hash,redirect_uri,expiration_timestamp) VALUES('\x07','google',$1,$2,'\x08','https://example.test',now())`
		rejected(t, db, "23514", q, nil, nil)
		rejected(t, db, "23514", q, challenge, session)
		execute(t, db, q, challenge, nil)
	})
	t.Run("registration accepts pending email only", func(t *testing.T) {
		execute(t, db, `INSERT INTO registrations(authentication_id,email) VALUES($1,'registration@example.test')`, auth)
		rejected(t, db, "23514", `INSERT INTO authentication_steps(step_id,authentication_id,type,expiration_timestamp) VALUES($1,$2,'passkeyRegistration',now())`, uuid.New(), auth)
	})
	t.Run("backup state requires eligible", func(t *testing.T) {
		rejected(t, db, "23514", `INSERT INTO passkeys(passkey_id,account_id,credential_id,public_key,name,sign_count,backup_eligible,backup_state) VALUES($1,$2,'\x09','\x0a','test',0,false,true)`, uuid.New(), account)
	})
	t.Run("totp prevents negative step", func(t *testing.T) {
		rejected(t, db, "23514", `INSERT INTO totp(account_id,encrypted_secret,last_used_step,activation_timestamp) VALUES($1,'\x0b',-1,now())`, account)
	})
	t.Run("backup single use delete", func(t *testing.T) {
		execute(t, db, `INSERT INTO backup_codes(account_id,code_hash,generation_timestamp) VALUES($1,'\x0c',now())`, account)
		for i := 0; i < 2; i++ {
			res, err := db.Exec(`DELETE FROM backup_codes WHERE account_id=$1 AND code_hash='\x0c'`, account)
			if err != nil {
				t.Fatal(err)
			}
			n, err := res.RowsAffected()
			if err != nil || n != int64(1-i) {
				t.Fatal("backup code was not consumed once")
			}
		}
	})
	t.Run("account deletion cascades", func(t *testing.T) {
		execute(t, db, `DELETE FROM accounts WHERE account_id=$1`, account)
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM sessions WHERE session_id=$1`, session).Scan(&n); err != nil || n != 0 {
			t.Fatal("session survived account deletion")
		}
	})
}
