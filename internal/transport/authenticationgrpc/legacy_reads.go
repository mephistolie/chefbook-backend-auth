package authenticationgrpc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	pb "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// LegacyReads serves the internal read RPCs still used by profile and gateway.
// All legacy mutation RPCs deliberately remain Unimplemented: their credentials
// and session flows must not bypass AuthenticationService policies.
type LegacyReads struct {
	pb.UnimplementedAuthServiceServer
	DB        *sql.DB
	PublicKey []byte
}

var _ pb.AuthServiceServer = (*LegacyReads)(nil)

func legacyReadError(err error) error {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return rpcError(codes.NotFound, "not_found")
	case errors.Is(err, context.Canceled):
		return rpcError(codes.Canceled, "request_cancelled")
	case errors.Is(err, context.DeadlineExceeded):
		return rpcError(codes.DeadlineExceeded, "request_timeout")
	default:
		return rpcError(codes.Internal, "auth_lookup_failed")
	}
}

func (s *LegacyReads) GetAccessTokenPublicKey(context.Context, *pb.GetAccessTokenPublicKeyRequest) (*pb.GetAccessTokenPublicKeyResponse, error) {
	if len(s.PublicKey) == 0 {
		return nil, rpcError(codes.Unavailable, "public_key_unavailable")
	}
	return &pb.GetAccessTokenPublicKeyResponse{PublicKey: append([]byte(nil), s.PublicKey...)}, nil
}

func (s *LegacyReads) GetAuthInfo(ctx context.Context, req *pb.GetAuthInfoRequest) (*pb.GetAuthInfoResponse, error) {
	var predicates []string
	var args []any
	add := func(column string, value any) {
		args = append(args, value)
		predicates = append(predicates, fmt.Sprintf("a.%s=$%d", column, len(args)))
	}
	if id := req.GetId(); id != "" {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil {
			return nil, rpcError(codes.InvalidArgument, "invalid_request")
		}
		add("account_id", parsed.String())
	}
	if email := strings.TrimSpace(req.GetEmail()); email != "" {
		add("email", strings.ToLower(email))
	}
	if username := strings.TrimSpace(req.GetUsername()); username != "" {
		add("username", username)
	}
	if len(args) == 0 {
		return nil, rpcError(codes.InvalidArgument, "invalid_request")
	}
	if s.DB == nil {
		return nil, rpcError(codes.Unavailable, "auth_storage_unavailable")
	}
	const query = `SELECT a.account_id,a.email,a.username,a.creation_timestamp,
 a.email_verification_timestamp,a.blocking_timestamp,d.deletion_timestamp,g.subject,v.subject
 FROM accounts a
 LEFT JOIN account_deletion_requests d ON d.account_id=a.account_id
 LEFT JOIN identities g ON g.account_id=a.account_id AND g.provider='google'
 LEFT JOIN identities v ON v.account_id=a.account_id AND v.provider='vk'
 WHERE `
	out := &pb.GetAuthInfoResponse{Role: "user"}
	var username, google, vk sql.NullString
	var created time.Time
	var verified, blocked, deleted sql.NullTime
	err := s.DB.QueryRowContext(ctx, query+strings.Join(predicates, " AND "), args...).Scan(
		&out.Id, &out.Email, &username, &created, &verified, &blocked, &deleted, &google, &vk,
	)
	if err != nil {
		return nil, legacyReadError(err)
	}
	out.RegistrationTimestamp = timestamppb.New(created)
	out.IsActivated = verified.Valid
	out.IsBlocked = blocked.Valid
	if username.Valid {
		out.Username = &username.String
	}
	if deleted.Valid {
		out.DeletionTimestamp = timestamppb.New(deleted.Time)
	}
	if google.Valid || vk.Valid {
		out.OAuth = &pb.OAuth{}
		if google.Valid {
			out.OAuth.GoogleId = &google.String
		}
		if vk.Valid {
			id, err := strconv.ParseInt(vk.String, 10, 64)
			if err != nil || id <= 0 {
				return nil, rpcError(codes.Internal, "invalid_identity")
			}
			out.OAuth.VkId = &id
		}
	}
	return out, nil
}

func (s *LegacyReads) GetVisibleNames(ctx context.Context, req *pb.GetVisibleNamesRequest) (*pb.GetVisibleNamesResponse, error) {
	out := &pb.GetVisibleNamesResponse{UserVisibleNames: map[string]string{}}
	var args []any
	var placeholders []string
	seen := map[uuid.UUID]bool{}
	for _, raw := range req.GetUserIds() {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil {
			return nil, rpcError(codes.InvalidArgument, "invalid_request")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		args = append(args, id.String())
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	if len(args) == 0 {
		return out, nil
	}
	if s.DB == nil {
		return nil, rpcError(codes.Unavailable, "auth_storage_unavailable")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT account_id,username FROM accounts WHERE username IS NOT NULL AND account_id IN (`+strings.Join(placeholders, ",")+")", args...)
	if err != nil {
		return nil, legacyReadError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err = rows.Scan(&id, &name); err != nil {
			return nil, legacyReadError(err)
		}
		out.UserVisibleNames[id] = name
	}
	if err = rows.Err(); err != nil {
		return nil, legacyReadError(err)
	}
	return out, nil
}

func (s *LegacyReads) GetProfileDeletionStatus(ctx context.Context, req *pb.GetProfileDeletionStatusRequest) (*pb.GetProfileDeletionStatusResponse, error) {
	id, err := uuid.Parse(req.GetProfileId())
	if err != nil || id == uuid.Nil {
		return nil, rpcError(codes.InvalidArgument, "invalid_request")
	}
	if s.DB == nil {
		return nil, rpcError(codes.Unavailable, "auth_storage_unavailable")
	}
	var deadline sql.NullTime
	err = s.DB.QueryRowContext(ctx, `SELECT d.deletion_timestamp FROM accounts a LEFT JOIN account_deletion_requests d ON d.account_id=a.account_id WHERE a.account_id=$1`, id.String()).Scan(&deadline)
	if errors.Is(err, sql.ErrNoRows) {
		return &pb.GetProfileDeletionStatusResponse{Deleted: true}, nil
	}
	if err != nil {
		return nil, legacyReadError(err)
	}
	out := &pb.GetProfileDeletionStatusResponse{}
	if deadline.Valid {
		out.DeletionTimestamp = timestamppb.New(deadline.Time)
	}
	return out, nil
}
