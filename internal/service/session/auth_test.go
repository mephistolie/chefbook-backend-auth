package session

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	authFail "github.com/mephistolie/chefbook-backend-auth/internal/entity/fail"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	emailService "github.com/mephistolie/chefbook-backend-auth/internal/service/email"
	"github.com/mephistolie/chefbook-backend-common/responses/fail"
	"testing"
)

type authRepo struct {
	repository.Data
	info                       entity.AuthInfo
	lookupError, errorSessions error
	binding                    *entity.EmailBinding
	allDeleted                 bool
	deletedIDs                 []int64
}

func (r *authRepo) GetAuthInfoByEmail(context.Context, string) (entity.AuthInfo, error) {
	return r.info, r.lookupError
}
func (r *authRepo) GetAuthInfoByIdentifiers(context.Context, entity.UserIdentifiers) (entity.AuthInfo, error) {
	return r.info, r.lookupError
}
func (r *authRepo) StartEmailBinding(_ context.Context, b entity.EmailBinding) error {
	r.binding = &b
	return nil
}
func (r *authRepo) GetSessions(context.Context, uuid.UUID) ([]entity.SessionRawInfo, error) {
	return nil, r.errorSessions
}
func (r *authRepo) DeleteAllSessions(context.Context, uuid.UUID) error {
	r.allDeleted = true
	return r.errorSessions
}
func (r *authRepo) DeleteSessions(_ context.Context, _ uuid.UUID, ids []int64) error {
	r.deletedIDs = ids
	return r.errorSessions
}

type testHash struct{}

func (testHash) Hash(value string) (string, error) { return "hash:" + value, nil }
func (testHash) Validate(value, hash string) error {
	if hash == "hash:"+value {
		return nil
	}
	return errors.New("wrong password")
}
func TestSignInDoesNotRevealBlockedAccountWithoutPassword(t *testing.T) {
	r := &authRepo{info: entity.AuthInfo{Id: uuid.New(), IsActivated: true, IsBlocked: true, PasswordHash: "hash:correct"}}
	s := Service{repo: r, hashManager: testHash{}}
	email := "a@example.com"
	for _, tc := range []struct {
		password string
		want     error
	}{{"wrong", authFail.GrpcInvalidCredentials}, {"correct", authFail.GrpcProfileIsBlocked}} {
		_, err := s.SignIn(context.Background(), entity.SignInCredentials{Email: &email, Password: tc.password}, entity.ClientData{})
		if err != tc.want {
			t.Fatalf("password=%s err=%v", tc.password, err)
		}
	}
}
func TestSignupStagesPasswordUntilEmailProof(t *testing.T) {
	r := &authRepo{info: entity.AuthInfo{Id: uuid.New(), Email: "a@example.com", PasswordHash: "hash:old"}}
	s := Service{repo: r, hashManager: testHash{}, email: emailService.New(r, nil, nil)}
	_, activated, err := s.SignUp(context.Background(), entity.SignUpCredentials{Email: r.info.Email, Password: "new"}, "https://example.com/confirm?token=%s")
	if err != nil || activated || r.binding == nil || r.binding.PasswordHash == nil || *r.binding.PasswordHash != "hash:new" {
		t.Fatalf("password not staged: %+v %v", r.binding, err)
	}
	if r.info.PasswordHash != "hash:old" {
		t.Fatal("password changed before email proof")
	}
	r.binding = nil
	r.info.IsActivated = true
	if _, _, err = s.SignUp(context.Background(), entity.SignUpCredentials{Email: r.info.Email, Password: "new"}, "pattern"); err != nil || r.binding != nil {
		t.Fatal("existing activated account must be uniform no-op")
	}
}
func TestSessionRepositoryFailurePropagates(t *testing.T) {
	r := &authRepo{errorSessions: fail.GrpcUnknown}
	s := Service{repo: r}
	if _, err := s.GetAll(context.Background(), uuid.New()); err != fail.GrpcUnknown {
		t.Fatal("GET swallowed failure")
	}
	if err := s.DeleteMultiple(context.Background(), uuid.New(), nil); err != fail.GrpcUnknown || !r.allDeleted {
		t.Fatal("DELETE all swallowed failure")
	}
	if err := s.DeleteMultiple(context.Background(), uuid.New(), []int64{42}); err != fail.GrpcUnknown || len(r.deletedIDs) != 1 {
		t.Fatal("DELETE one swallowed failure")
	}
}
func TestClientMetadataDoesNotAssumeMobileMeansApp(t *testing.T) {
	for _, tc := range []struct{ ua, platform, kind string }{{"", "unknown", "unknown"}, {"ChefBook/1 Android", "android", "app"}, {"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1", "ios", "browser"}} {
		c := parseClient(tc.ua)
		if c.Platform != tc.platform || c.Type != tc.kind {
			t.Fatalf("%q -> %+v", tc.ua, c)
		}
	}
}
