package authenticationgrpc

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	pb "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	engine "github.com/mephistolie/chefbook-backend-auth/internal/authentication"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Server struct {
	pb.UnimplementedAuthenticationServiceServer
	Engine                               *engine.Engine
	Issuer                               engine.TokenIssuer
	AccessTTL, RefreshTTL, DeletionDelay time.Duration
	PasswordResetURL, EmailChangeURL     string
}

func rpcError(code codes.Code, reason string) error {
	s, e := status.New(code, reason).WithDetails(&errdetails.ErrorInfo{Reason: reason})
	if e != nil {
		return status.Error(codes.Internal, "authentication operation failed")
	}
	return s.Err()
}
func failure(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, engine.ErrNotFound):
		return rpcError(codes.NotFound, err.Error())
	case errors.Is(err, engine.ErrSession):
		return rpcError(codes.Unauthenticated, err.Error())
	case errors.Is(err, engine.ErrInvalid):
		return rpcError(codes.InvalidArgument, err.Error())
	case errors.Is(err, engine.ErrUnauthorized):
		return rpcError(codes.NotFound, err.Error())
	case errors.Is(err, engine.ErrCredentials):
		return rpcError(codes.InvalidArgument, err.Error())
	case errors.Is(err, engine.ErrForbidden):
		return rpcError(codes.PermissionDenied, err.Error())
	case errors.Is(err, engine.ErrConflict), errors.Is(err, engine.ErrAccountExists):
		return rpcError(codes.FailedPrecondition, err.Error())
	case errors.Is(err, engine.ErrAttempts):
		return rpcError(codes.ResourceExhausted, err.Error())
	case errors.Is(err, engine.ErrUnavailable):
		return rpcError(codes.Unavailable, err.Error())
	}
	return rpcError(codes.Internal, "authentication operation failed")
}
func principal(p *pb.AuthPrincipal) engine.Principal {
	if p == nil {
		return engine.Principal{}
	}
	id, _ := uuid.Parse(p.AccountId)
	return engine.Principal{AccountID: id, SessionID: p.SessionId}
}
func flow(f *pb.FlowContext) (uuid.UUID, string, engine.Principal, error) {
	if f == nil {
		return uuid.Nil, "", engine.Principal{}, engine.ErrInvalid
	}
	id, err := uuid.Parse(f.AuthenticationId)
	if err != nil {
		return id, "", engine.Principal{}, engine.ErrInvalid
	}
	return id, f.FlowToken, principal(f.Principal), nil
}
func state(p engine.Process) *pb.AuthenticationState {
	s := &pb.AuthenticationState{Id: p.ID.String(), Purpose: p.Purpose.Type, Status: p.Status, ExpirationTimestamp: timestamppb.New(p.ExpirationTimestamp), Options: stepOptions(p.Next.Methods), FlowToken: p.FlowToken, ConfirmationToken: p.ConfirmationToken}
	if p.ConfirmationExpirationTimestamp != nil {
		s.ConfirmationExpirationTimestamp = timestamppb.New(*p.ConfirmationExpirationTimestamp)
	}
	for _, c := range p.Steps {
		s.Steps = append(s.Steps, challenge(c))
	}
	return s
}
func stepOptions(methods []string) []string {
	out := []string{}
	for _, m := range methods {
		out = append(out, engine.StepType(m))
	}
	return out
}
func challenge(c engine.Challenge) *pb.AuthenticationStep {
	p := &pb.AuthenticationStep{PublicKeyOptions: c.PublicKey, Url: c.URL, Nonce: c.Nonce, Id: c.ID.String(), Type: engine.StepType(c.Method), Status: c.Status, ExpirationTimestamp: timestamppb.New(c.ExpirationTimestamp)}
	if c.Method == "email" {
		p.CodeLength = 6
	}
	return p
}
func tokens(t engine.Tokens) *pb.AuthTokens {
	p := &pb.AuthTokens{UserId: t.UserID.String(), SessionId: t.SessionID, AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, ExpirationTimestamp: timestamppb.New(t.ExpirationTimestamp)}
	for _, r := range t.Restrictions {
		p.Restrictions = append(p.Restrictions, &pb.AuthRestriction{Type: r.Type, DeletionTimestamp: timestamppb.New(r.DeletionTimestamp), DeleteSharedData: r.DeleteSharedData})
	}
	return p
}
func action(a *pb.SensitiveAction) (engine.Principal, string) {
	if a == nil {
		return engine.Principal{}, ""
	}
	return principal(a.Principal), a.ConfirmationToken
}
func (s *Server) CreateAuthentication(ctx context.Context, r *pb.CreateAuthenticationRequest) (*pb.AuthenticationState, error) {
	req := engine.StartRequest{Purpose: engine.Purpose{Type: r.Purpose}}
	p, err := s.Engine.Start(ctx, req, principal(r.Principal))
	if err != nil {
		return nil, failure(err)
	}
	return state(p), nil
}
func (s *Server) GetAuthentication(ctx context.Context, r *pb.FlowContext) (*pb.AuthenticationState, error) {
	id, t, p, err := flow(r)
	if err != nil {
		return nil, failure(err)
	}
	v, err := s.Engine.Get(ctx, id, t, p)
	if err != nil {
		return nil, failure(err)
	}
	return state(v), nil
}
func (s *Server) StartAuthenticationStep(ctx context.Context, r *pb.StartAuthenticationStepRequest) (*pb.AuthenticationStep, error) {
	if !validStepType(r.Type) {
		return nil, failure(engine.ErrInvalid)
	}
	id, t, p, err := flow(r.Flow)
	if err != nil {
		return nil, failure(err)
	}
	v, err := s.Engine.CreateChallenge(ctx, id, t, engine.StepMethod(r.Type), p, engine.OAuthOptions{CredentialType: r.CredentialType, RedirectURI: r.RedirectUri})
	if err != nil {
		return nil, failure(err)
	}
	return challenge(v), nil
}

func validStepType(value string) bool {
	switch value {
	case "registration", "passwordSetup", "passwordVerification", "emailVerification", "totpVerification", "backupCodeVerification", "googleVerification", "vkVerification", "passkeyVerification":
		return true
	}
	return false
}
func (s *Server) GetAuthenticationStep(ctx context.Context, r *pb.AuthenticationStepContext) (*pb.AuthenticationStep, error) {
	id, t, p, err := flow(r.Flow)
	if err != nil {
		return nil, failure(err)
	}
	cid, err := uuid.Parse(r.StepId)
	if err != nil {
		return nil, failure(engine.ErrInvalid)
	}
	v, err := s.Engine.GetChallenge(ctx, id, cid, t, p)
	if err != nil {
		return nil, failure(err)
	}
	return challenge(v), nil
}
func (s *Server) CompleteAuthenticationStep(ctx context.Context, r *pb.CompleteAuthenticationStepRequest) (*pb.CompleteAuthenticationStepResponse, error) {
	if r.Step == nil {
		return nil, failure(engine.ErrInvalid)
	}
	id, t, p, err := flow(r.Step.Flow)
	if err != nil {
		return nil, failure(err)
	}
	cid, err := uuid.Parse(r.Step.StepId)
	if err != nil {
		return nil, failure(engine.ErrInvalid)
	}
	proof := engine.Proof{}
	switch v := r.Proof.(type) {
	case *pb.CompleteAuthenticationStepRequest_Registration:
		proof = engine.Proof{Method: "registration", Email: v.Registration.Email}
	case *pb.CompleteAuthenticationStepRequest_PasswordSetup:
		proof = engine.Proof{Method: "passwordSetup", Password: v.PasswordSetup.Password}

	case *pb.CompleteAuthenticationStepRequest_Google:
		proof = engine.Proof{Method: "google", Code: v.Google.Code, State: v.Google.State, IDToken: v.Google.IdToken}
	case *pb.CompleteAuthenticationStepRequest_Vk:
		proof = engine.Proof{Method: "vk", Code: v.Vk.Code, State: v.Vk.State}
	case *pb.CompleteAuthenticationStepRequest_Passkey:
		proof = engine.Proof{Method: "passkey", Credential: v.Passkey.Credential}
	case *pb.CompleteAuthenticationStepRequest_Password:
		proof = engine.Proof{Method: "password", Login: v.Password.Login, Password: v.Password.Password}
	case *pb.CompleteAuthenticationStepRequest_Email:
		proof = engine.Proof{Method: "email", Code: v.Email.Code}
	case *pb.CompleteAuthenticationStepRequest_Totp:
		proof = engine.Proof{Method: "totp", Code: v.Totp.Code}
	case *pb.CompleteAuthenticationStepRequest_BackupCode:
		proof = engine.Proof{Method: "backupCode", Code: v.BackupCode.Code}
	default:
		return nil, failure(engine.ErrUnavailable)
	}
	var v engine.Attempt
	if proof.Method == "google" || proof.Method == "vk" {
		v, err = s.Engine.AttemptProvider(ctx, id, cid, t, p, proof)
	} else {
		v, err = s.Engine.Attempt(ctx, id, cid, t, p, proof)
	}
	if err != nil {
		return nil, failure(err)
	}
	return &pb.CompleteAuthenticationStepResponse{Step: challenge(v.Challenge), Authentication: state(v.Authentication)}, nil
}
func (s *Server) CreateSession(ctx context.Context, r *pb.CreateAuthenticatedSessionRequest) (*pb.AuthTokens, error) {
	v, err := s.Engine.CreateSession(ctx, r.AuthenticationToken, r.Ip, r.UserAgent, s.Issuer, s.AccessTTL, s.RefreshTTL)
	if err != nil {
		return nil, failure(err)
	}
	return tokens(v), nil
}
func (s *Server) RefreshSession(ctx context.Context, r *pb.RotateSessionRequest) (*pb.AuthTokens, error) {
	v, err := s.Engine.Refresh(ctx, r.SessionId, r.RefreshToken, r.Ip, r.UserAgent, s.Issuer, s.AccessTTL, s.RefreshTTL)
	if errors.Is(err, engine.ErrCredentials) {
		return nil, rpcError(codes.InvalidArgument, "invalid_refresh_token")
	}
	if err != nil {
		return nil, failure(err)
	}
	return tokens(v), nil
}
func (s *Server) RevokeSessions(ctx context.Context, r *pb.RevokeAuthSessionRequest) (*emptypb.Empty, error) {
	var err error
	if r.RefreshToken != "" {
		if r.SessionId == nil {
			return nil, failure(engine.ErrInvalid)
		}
		err = s.Engine.LogoutRefresh(ctx, *r.SessionId, r.RefreshToken)
	} else {
		err = s.Engine.RevokeSessions(ctx, principal(r.Principal), r.SessionId)
	}
	return &emptypb.Empty{}, failure(err)
}
func (s *Server) SetPassword(ctx context.Context, r *pb.SetAccountPasswordRequest) (*emptypb.Empty, error) {
	p, t := action(r.Action)
	return &emptypb.Empty{}, failure(s.Engine.SetPassword(ctx, p, t, r.NewPassword))
}
func (s *Server) SetUsername(ctx context.Context, r *pb.SetAccountUsernameRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, failure(s.Engine.SetUsername(ctx, principal(r.Principal), r.Username))
}
func (s *Server) UsernameAvailability(ctx context.Context, r *pb.AuthUsernameRequest) (*pb.AuthUsernameAvailability, error) {
	v, err := s.Engine.UsernameAvailable(ctx, r.Username)
	return &pb.AuthUsernameAvailability{Available: v}, failure(err)
}
func (s *Server) StartPasswordReset(ctx context.Context, r *pb.StartPasswordResetRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, failure(s.Engine.StartPasswordReset(ctx, r.Email, s.PasswordResetURL))
}
func (s *Server) ConfirmPasswordReset(ctx context.Context, r *pb.ConfirmPasswordResetRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, failure(s.Engine.ConfirmPasswordReset(ctx, r.Token, r.NewPassword))
}
func (s *Server) ChangeEmail(ctx context.Context, r *pb.ChangeAccountEmailRequest) (*emptypb.Empty, error) {
	p, t := action(r.Action)
	return &emptypb.Empty{}, failure(s.Engine.ChangeEmail(ctx, p, t, r.Email, s.EmailChangeURL))
}
func (s *Server) ConfirmEmail(ctx context.Context, r *pb.ConfirmAccountEmailRequest) (*pb.ConfirmAccountEmailResponse, error) {
	v, err := s.Engine.ConfirmEmail(ctx, r.Token, s.EmailChangeURL)
	return &pb.ConfirmAccountEmailResponse{Status: v}, failure(err)
}
func deletion(d engine.Deletion) *pb.AccountDeletion {
	return &pb.AccountDeletion{DeletionTimestamp: timestamppb.New(d.DeletionTimestamp), DeleteSharedData: d.DeleteSharedData}
}
func (s *Server) RequestDeletion(ctx context.Context, r *pb.RequestAccountDeletionRequest) (*pb.AccountDeletion, error) {
	p, t := action(r.Action)
	v, err := s.Engine.RequestDeletion(ctx, p, t, r.DeleteSharedData, s.DeletionDelay)
	return deletion(v), failure(err)
}
func (s *Server) PatchDeletion(ctx context.Context, r *pb.PatchAccountDeletionRequest) (*pb.AccountDeletion, error) {
	v, err := s.Engine.PatchDeletion(ctx, principal(r.Principal), r.DeleteSharedData)
	return deletion(v), failure(err)
}
func (s *Server) CancelDeletion(ctx context.Context, r *pb.AuthPrincipal) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, failure(s.Engine.CancelDeletion(ctx, principal(r)))
}
func (s *Server) GetTotp(ctx context.Context, r *pb.AuthPrincipal) (*pb.TotpState, error) {
	v, err := s.Engine.GetTotp(ctx, principal(r))
	out := &pb.TotpState{Enabled: v.Enabled}
	if v.ActivationTimestamp != nil {
		out.ActivationTimestamp = timestamppb.New(*v.ActivationTimestamp)
	}
	return out, failure(err)
}
func (s *Server) StartTotp(ctx context.Context, r *pb.SensitiveAction) (*pb.TotpActivation, error) {
	p, t := action(r)
	v, err := s.Engine.StartTotp(ctx, p, t)
	return &pb.TotpActivation{Secret: v.Secret, OtpauthUri: v.OtpauthURI, ExpirationTimestamp: timestamppb.New(v.ExpirationTimestamp)}, failure(err)
}
func backup(v engine.BackupCodes) *pb.BackupCodes {
	return &pb.BackupCodes{Codes: v.Codes, GenerationTimestamp: timestamppb.New(v.GenerationTimestamp)}
}
func (s *Server) ConfirmTotp(ctx context.Context, r *pb.ConfirmTotpRequest) (*pb.BackupCodes, error) {
	v, err := s.Engine.ConfirmTotp(ctx, principal(r.Principal), r.Code)
	return backup(v), failure(err)
}
func (s *Server) DeleteTotp(ctx context.Context, r *pb.SensitiveAction) (*emptypb.Empty, error) {
	p, t := action(r)
	return &emptypb.Empty{}, failure(s.Engine.DeleteTotp(ctx, p, t))
}
func (s *Server) GetBackupCodes(ctx context.Context, r *pb.AuthPrincipal) (*pb.BackupCodesState, error) {
	v, err := s.Engine.GetBackupCodes(ctx, principal(r))
	out := &pb.BackupCodesState{RemainingCount: int32(v.RemainingCount)}
	if v.GenerationTimestamp != nil {
		out.GenerationTimestamp = timestamppb.New(*v.GenerationTimestamp)
	}
	return out, failure(err)
}
func (s *Server) RotateBackupCodes(ctx context.Context, r *pb.SensitiveAction) (*pb.BackupCodes, error) {
	p, t := action(r)
	v, err := s.Engine.RotateBackupCodes(ctx, p, t)
	return backup(v), failure(err)
}
func (s *Server) ValidateSession(ctx context.Context, r *pb.AuthPrincipal) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, failure(s.Engine.ValidateSession(ctx, principal(r)))
}
func (s *Server) GetSessions(ctx context.Context, r *pb.AuthPrincipal) (*pb.AuthSessions, error) {
	v, err := s.Engine.GetSessions(ctx, principal(r))
	if err != nil {
		return nil, failure(err)
	}
	out := &pb.AuthSessions{}
	for _, session := range v {
		out.Sessions = append(out.Sessions, &pb.AuthSession{Id: session.ID, Ip: session.IP, UserAgent: session.UserAgent, LastRefreshTimestamp: timestamppb.New(session.LastRefreshTimestamp)})
	}
	return out, nil
}

func passkey(p engine.Passkey) *pb.AuthPasskey {
	out := &pb.AuthPasskey{Id: p.ID.String(), Name: p.Name, CreationTimestamp: timestamppb.New(p.CreationTimestamp), Transports: p.Transports, BackupEligible: p.BackupEligible, BackupState: p.BackupState}
	if p.LastUseTimestamp != nil {
		out.LastUseTimestamp = timestamppb.New(*p.LastUseTimestamp)
	}
	return out
}
func (s *Server) GetPasskeys(ctx context.Context, r *pb.AuthPrincipal) (*pb.AuthPasskeys, error) {
	v, err := s.Engine.GetPasskeys(ctx, principal(r))
	if err != nil {
		return nil, failure(err)
	}
	out := &pb.AuthPasskeys{}
	for _, p := range v {
		out.Passkeys = append(out.Passkeys, passkey(p))
	}
	return out, nil
}
func (s *Server) StartPasskeyRegistration(ctx context.Context, r *pb.SensitiveAction) (*pb.PasskeyRegistrationOptions, error) {
	p, t := action(r)
	v, err := s.Engine.StartPasskey(ctx, p, t)
	if err != nil {
		return nil, failure(err)
	}
	return &pb.PasskeyRegistrationOptions{RequestId: v.ID.String(), PublicKeyOptions: v.PublicKey, ExpirationTimestamp: timestamppb.New(v.ExpirationTimestamp)}, nil
}
func (s *Server) RegisterPasskey(ctx context.Context, r *pb.RegisterAuthPasskeyRequest) (*pb.AuthPasskey, error) {
	id, err := uuid.Parse(r.RequestId)
	if err != nil {
		return nil, failure(engine.ErrInvalid)
	}
	v, err := s.Engine.RegisterPasskey(ctx, principal(r.Principal), id, r.Name, r.Credential)
	if err != nil {
		return nil, failure(err)
	}
	return passkey(v), nil
}
func (s *Server) RenamePasskey(ctx context.Context, r *pb.RenameAuthPasskeyRequest) (*pb.AuthPasskey, error) {
	id, err := uuid.Parse(r.Id)
	if err != nil {
		return nil, failure(engine.ErrInvalid)
	}
	v, err := s.Engine.RenamePasskey(ctx, principal(r.Principal), id, r.Name)
	if err != nil {
		return nil, failure(err)
	}
	return passkey(v), nil
}
func (s *Server) DeletePasskey(ctx context.Context, r *pb.DeleteAuthPasskeyRequest) (*emptypb.Empty, error) {
	id, err := uuid.Parse(r.Id)
	if err != nil {
		return nil, failure(engine.ErrInvalid)
	}
	p, t := action(r.Action)
	return &emptypb.Empty{}, failure(s.Engine.DeletePasskey(ctx, p, t, id))
}

func (s *Server) GetIdentities(ctx context.Context, r *pb.AuthPrincipal) (*pb.AuthIdentities, error) {
	v, err := s.Engine.GetIdentities(ctx, principal(r))
	if err != nil {
		return nil, failure(err)
	}
	out := &pb.AuthIdentities{}
	for _, i := range v {
		out.Identities = append(out.Identities, &pb.AuthIdentity{Provider: i.Provider, Subject: i.Subject})
	}
	return out, nil
}
func (s *Server) PrepareIdentityOAuth(ctx context.Context, r *pb.PrepareIdentityOAuthRequest) (*pb.PreparedIdentityOAuth, error) {
	v, err := s.Engine.PrepareIdentityOAuth(ctx, principal(r.Principal), r.Provider, r.RedirectUri)
	if err != nil {
		return nil, failure(err)
	}
	return &pb.PreparedIdentityOAuth{Url: v.URL, ExpirationTimestamp: timestamppb.New(v.ExpirationTimestamp)}, nil
}
func (s *Server) LinkIdentity(ctx context.Context, r *pb.LinkIdentityRequest) (*pb.LinkIdentityResponse, error) {
	p, t := action(r.Action)
	v, err := s.Engine.LinkIdentity(ctx, p, t, r.Provider, r.Code, r.State)
	return &pb.LinkIdentityResponse{Created: v}, failure(err)
}
func (s *Server) UnlinkIdentity(ctx context.Context, r *pb.UnlinkIdentityRequest) (*emptypb.Empty, error) {
	p, t := action(r.Action)
	return &emptypb.Empty{}, failure(s.Engine.UnlinkIdentity(ctx, p, t, r.Provider))
}
