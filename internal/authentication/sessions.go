package authentication

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-common/tokens/access"
)

type TokenIssuer interface {
	CreateAccess(access.Payload, time.Duration) (string, error)
}
type Tokens struct {
	UserID              uuid.UUID     `json:"userId"`
	SessionID           int64         `json:"sessionId"`
	AccessToken         string        `json:"accessToken"`
	RefreshToken        string        `json:"refreshToken"`
	ExpirationTimestamp time.Time     `json:"expirationTimestamp"`
	Restrictions        []Restriction `json:"restrictions"`
}
type Restriction struct {
	Type              string    `json:"type"`
	DeletionTimestamp time.Time `json:"deletionTimestamp"`
	DeleteSharedData  bool      `json:"deleteSharedData"`
}

func (e *Engine) CreateSession(ctx context.Context, grant, ip, ua string, issuer TokenIssuer, accessTTL, refreshTTL time.Duration) (Tokens, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return Tokens{}, err
	}
	defer tx.Rollback()
	var purpose string
	err = tx.QueryRowContext(ctx, `SELECT purpose FROM authentications WHERE confirmation_token_hash=$1`, e.Secrets.Hash("grant", "", grant)).Scan(&purpose)
	if errors.Is(err, sql.ErrNoRows) {
		return Tokens{}, ErrForbidden
	}
	if err != nil {
		return Tokens{}, err
	}
	if purpose != "signIn" && purpose != "signUp" {
		return Tokens{}, ErrForbidden
	}
	account, err := e.ConsumeGrant(ctx, tx, grant, purpose, Principal{})
	if err != nil {
		return Tokens{}, err
	}
	refresh, err := randomToken()
	if err != nil {
		return Tokens{}, err
	}
	expiry := e.Now().Add(refreshTTL)
	var id int64
	err = tx.QueryRowContext(ctx, `INSERT INTO sessions(account_id,refresh_token_hash,ip,user_agent,expiration_timestamp) VALUES($1,$2,$3,$4,$5) RETURNING session_id`, account, e.Secrets.Hash("refresh", "", refresh), ip, ua, expiry).Scan(&id)
	if err != nil {
		return Tokens{}, err
	}
	result, err := e.issue(ctx, tx, account, id, refresh, expiry, issuer, accessTTL)
	if err != nil {
		return Tokens{}, err
	}
	if err = e.notifyAccount(ctx, tx, account, mailRequest{Template: "new_login", Client: ua}); err != nil {
		return Tokens{}, err
	}
	if err = tx.Commit(); err != nil {
		return Tokens{}, err
	}
	return result, nil
}
func (e *Engine) Refresh(ctx context.Context, id int64, refresh, ip, ua string, issuer TokenIssuer, accessTTL, refreshTTL time.Duration) (Tokens, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return Tokens{}, err
	}
	defer tx.Rollback()
	var account uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT account_id FROM sessions WHERE session_id=$1 AND refresh_token_hash=$2 AND expiration_timestamp>$3 FOR UPDATE`, id, e.Secrets.Hash("refresh", "", refresh), e.Now()).Scan(&account)
	if errors.Is(err, sql.ErrNoRows) {
		return Tokens{}, ErrCredentials
	}
	if err != nil {
		return Tokens{}, err
	}
	next, err := randomToken()
	if err != nil {
		return Tokens{}, err
	}
	expiry := e.Now().Add(refreshTTL)
	_, err = tx.ExecContext(ctx, `UPDATE sessions SET refresh_token_hash=$2,ip=$3,user_agent=$4,last_refresh_timestamp=$5,expiration_timestamp=$6 WHERE session_id=$1`, id, e.Secrets.Hash("refresh", "", next), ip, ua, e.Now(), expiry)
	if err != nil {
		return Tokens{}, err
	}
	result, err := e.issue(ctx, tx, account, id, next, expiry, issuer, accessTTL)
	if err != nil {
		return Tokens{}, err
	}
	if err = tx.Commit(); err != nil {
		return Tokens{}, err
	}
	return result, nil
}
func (e *Engine) issue(ctx context.Context, tx *sql.Tx, account uuid.UUID, id int64, refresh string, expiry time.Time, issuer TokenIssuer, accessTTL time.Duration) (Tokens, error) {
	p := access.Payload{UserId: account, SessionID: id}
	var username sql.NullString
	var blocked sql.NullTime
	err := tx.QueryRowContext(ctx, `SELECT email,username,blocking_timestamp FROM accounts WHERE account_id=$1 FOR UPDATE`, account).Scan(&p.Email, &username, &blocked)
	if err != nil {
		return Tokens{}, err
	}
	if blocked.Valid {
		return Tokens{}, ErrForbidden
	}
	if username.Valid {
		p.Username = &username.String
	}
	result := Tokens{UserID: account, SessionID: id, RefreshToken: refresh, ExpirationTimestamp: expiry, Restrictions: []Restriction{}}
	var deletion Restriction
	err = tx.QueryRowContext(ctx, `SELECT deletion_timestamp,delete_shared_data FROM account_deletion_requests WHERE account_id=$1`, account).Scan(&deletion.DeletionTimestamp, &deletion.DeleteSharedData)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Tokens{}, err
	}
	if err == nil {
		if !deletion.DeletionTimestamp.After(e.Now()) {
			return Tokens{}, ErrForbidden
		}
		deletion.Type = "pendingDeletion"
		result.Restrictions = append(result.Restrictions, deletion)
		p.Deleted = true
	}
	result.AccessToken, err = issuer.CreateAccess(p, accessTTL)
	return result, err
}
func (e *Engine) RevokeSessions(ctx context.Context, who Principal, id *int64) error {
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = e.checkSession(ctx, tx, who); err != nil {
		return err
	}
	if id == nil {
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE account_id=$1`, who.AccountID)
	} else {
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE account_id=$1 AND session_id=$2`, who.AccountID, *id)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Engine) LogoutRefresh(ctx context.Context, id int64, refresh string) error {
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE session_id=$1 AND refresh_token_hash=$2`, id, e.Secrets.Hash("refresh", "", refresh))
	if err != nil {
		return err
	}
	return tx.Commit()
}

type Session struct {
	ID                   int64
	IP, UserAgent        string
	LastRefreshTimestamp time.Time
}

func (e *Engine) ValidateSession(ctx context.Context, who Principal) error {
	tx, err := e.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return e.checkSession(ctx, tx, who)
}
func (e *Engine) GetSessions(ctx context.Context, who Principal) ([]Session, error) {
	tx, err := e.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = e.checkRecoveryPrincipal(ctx, tx, who); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT session_id,host(ip),user_agent,last_refresh_timestamp FROM sessions WHERE account_id=$1 AND expiration_timestamp>$2 ORDER BY last_refresh_timestamp DESC`, who.AccountID, e.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var s Session
		if err = rows.Scan(&s.ID, &s.IP, &s.UserAgent, &s.LastRefreshTimestamp); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (e *Engine) checkSession(ctx context.Context, tx *sql.Tx, p Principal) error {
	var ok bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sessions WHERE session_id=$1 AND account_id=$2 AND expiration_timestamp>$3)`, p.SessionID, p.AccountID, e.Now()).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return ErrSession
	}
	return nil
}
