package password

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/mephistolie/chefbook-backend-auth/internal/entity"
	"github.com/mephistolie/chefbook-backend-auth/internal/service/dependencies/repository"
	"testing"
)

type passwordRepo struct {
	repository.Data
	info   entity.AuthInfo
	writes int
}

func (r *passwordRepo) GetAuthInfoById(context.Context, uuid.UUID) (entity.AuthInfo, error) {
	return r.info, nil
}
func (r *passwordRepo) SetPassword(_ context.Context, _ uuid.UUID, hash string) error {
	r.writes++
	r.info.PasswordHash = hash
	return nil
}

type passwordHash struct{}

func (passwordHash) Hash(p string) (string, error) { return "hash:" + p, nil }
func (passwordHash) Validate(p, h string) error {
	if h == "hash:"+p {
		return nil
	}
	return errors.New("bad password")
}
func TestPutPasswordRetryIsNoOp(t *testing.T) {
	r := &passwordRepo{info: entity.AuthInfo{Id: uuid.New(), PasswordHash: "hash:new"}}
	s := Service{repo: r, hashManager: passwordHash{}}
	if err := s.Change(context.Background(), r.info.Id, "old", "new"); err != nil || r.writes != 0 {
		t.Fatalf("retry should not mutate or notify: %v", err)
	}
}
