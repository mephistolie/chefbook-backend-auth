package authenticationgrpc

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	pb "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const legacyAccountID = "00000000-0000-4000-8000-000000000001"

func TestLegacyReadsAuthInfoUsesNewSchema(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	mock.ExpectQuery("SELECT a.account_id,a.email,a.username,a.creation_timestamp").WithArgs(legacyAccountID).WillReturnRows(sqlmock.NewRows([]string{"id", "email", "username", "created", "verified", "blocked", "deleted", "google", "vk"}).AddRow(legacyAccountID, "a@example.test", "alice", now, now, nil, now, "google-subject", "42"))
	got, err := (&LegacyReads{DB: db}).GetAuthInfo(context.Background(), &pb.GetAuthInfoRequest{Id: legacyAccountID})
	if err != nil {
		t.Fatal(err)
	}
	if got.Id != legacyAccountID || got.Role != "user" || !got.IsActivated || got.IsBlocked || got.GetUsername() != "alice" || got.OAuth.GetGoogleId() != "google-subject" || got.OAuth.GetVkId() != 42 || !got.DeletionTimestamp.AsTime().Equal(now) {
		t.Fatalf("unexpected compatibility response: %v", got)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestLegacyReadsFailureDoesNotPretendAccountDeleted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		code    codes.Code
		deleted bool
	}{
		{"missing", sql.ErrNoRows, codes.OK, true},
		{"storage", errors.New("password=secret database host"), codes.Internal, false},
		{"cancelled", context.Canceled, codes.Canceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery("SELECT d.deletion_timestamp FROM accounts").WithArgs(legacyAccountID).WillReturnError(tc.err)
			got, err := (&LegacyReads{DB: db}).GetProfileDeletionStatus(context.Background(), &pb.GetProfileDeletionStatusRequest{ProfileId: legacyAccountID})
			if status.Code(err) != tc.code {
				t.Fatalf("code=%v", status.Code(err))
			}
			if tc.deleted && (got == nil || !got.Deleted) {
				t.Fatal("missing account should be deleted")
			}
			if !tc.deleted && got != nil {
				t.Fatal("database failure must not report deletion")
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("leaked database detail")
			}
			if err = mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestLegacyReadsVisibleNamesDeduplicateAndNeverFallbackToEmail(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT account_id,username FROM accounts WHERE username IS NOT NULL").WithArgs(legacyAccountID).WillReturnRows(sqlmock.NewRows([]string{"account_id", "username"}).AddRow(legacyAccountID, "alice"))
	got, err := (&LegacyReads{DB: db}).GetVisibleNames(context.Background(), &pb.GetVisibleNamesRequest{UserIds: []string{legacyAccountID, legacyAccountID}})
	if err != nil || len(got.UserVisibleNames) != 1 || got.UserVisibleNames[legacyAccountID] != "alice" {
		t.Fatalf("unexpected visible names: %v %v", got, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestLegacyReadsRejectMalformedIdentityAndKeepMutationsDisabled(t *testing.T) {
	server := &LegacyReads{PublicKey: []byte("public")}
	_, err := server.GetAuthInfo(context.Background(), &pb.GetAuthInfoRequest{Id: "invalid", Email: "valid@example.test"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatal("invalid ID must not fallback to email")
	}
	_, err = server.SignIn(context.Background(), &pb.SignInRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatal("legacy authentication must remain disabled")
	}
	key, err := server.GetAccessTokenPublicKey(context.Background(), &pb.GetAccessTokenPublicKeyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	key.PublicKey[0] = 'x'
	if string(server.PublicKey) != "public" {
		t.Fatal("response aliased stored key")
	}
}
