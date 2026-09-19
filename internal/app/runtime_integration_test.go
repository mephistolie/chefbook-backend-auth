package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	pb "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/authenticationgrpc"
	"github.com/mephistolie/chefbook-backend-auth/schema"
	"github.com/mephistolie/chefbook-backend-common/tokens/access"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// This exercises actual protobuf transport, runtime key configuration, initial
// schema installer and PostgreSQL transactions. SMTP/providers stay disconnected.
func TestRuntimeRegistrationSessionLifecycle(t *testing.T) {
	dsn := os.Getenv("AUTH_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTH_TEST_DATABASE_URL unset")
	}
	dbcfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test database URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin := stdlib.OpenDB(*dbcfg)
	name := "auth_runtime_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	scoped := dbcfg.Copy()
	scoped.RuntimeParams["search_path"] = name
	db := stdlib.OpenDB(*scoped)
	t.Cleanup(func() {
		db.Close()
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	// Deliberately fail after every real DDL statement. This serial test restores
	// the embedded source immediately, including when Initialize reports failure.
	func() {
		original := schema.Initial
		defer func() { schema.Initial = original }()
		schema.Initial = original + "\nSELECT 1 / 0;"
		if err := schema.Initialize(ctx, db); err == nil {
			t.Fatal("failed DDL unexpectedly succeeded")
		}
	}()
	var remainingTables int
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM pg_tables WHERE schemaname=current_schema()").Scan(&remainingTables); err != nil {
		t.Fatal(err)
	}
	if remainingTables != 0 {
		t.Fatal("failed initial installation left committed tables")
	}
	if err = schema.Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = schema.Check(ctx, db); err != nil {
		t.Fatal(err)
	}
	mac := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	cipher := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	cfg := &config.Config{Environment: ptr(config.EnvDev), Security: config.Security{HMACKey: &mac, EncryptionKey: &cipher}, Auth: config.Auth{SaltCost: ptr(4)}}
	engine, issuer, err := configureEngine(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	pb.RegisterAuthenticationServiceServer(server, &authenticationgrpc.Server{Engine: engine, Issuer: issuer, AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour, DeletionDelay: 24 * time.Hour})
	pb.RegisterAuthServiceServer(server, &authenticationgrpc.LegacyReads{DB: db, PublicKey: x509.MarshalPKCS1PublicKey(issuer.GetAccessPublicKey())})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); listener.Close() })
	conn, err := grpc.NewClient("passthrough:///auth-runtime", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client := pb.NewAuthenticationServiceClient(conn)
	legacy := pb.NewAuthServiceClient(conn)
	email := uuid.NewString() + "@example.test"
	process, err := client.CreateAuthentication(ctx, &pb.CreateAuthenticationRequest{Purpose: "signUp"})
	if err != nil {
		t.Fatal(err)
	}
	if process.Status != "pending" || process.FlowToken == "" || process.ConfirmationToken != "" {
		t.Fatal("registration returned wrong process state")
	}
	var accounts, sessions int
	if err = db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM accounts),(SELECT count(*) FROM sessions)").Scan(&accounts, &sessions); err != nil {
		t.Fatal(err)
	}
	if accounts != 0 || sessions != 0 {
		t.Fatal("unverified registration created an account or session")
	}
	flow := &pb.FlowContext{AuthenticationId: process.Id, FlowToken: process.FlowToken}
	registration, err := client.StartAuthenticationStep(ctx, &pb.StartAuthenticationStepRequest{Flow: flow, Type: "registration"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.CompleteAuthenticationStep(ctx, &pb.CompleteAuthenticationStepRequest{Step: &pb.AuthenticationStepContext{Flow: flow, StepId: registration.Id}, Proof: &pb.CompleteAuthenticationStepRequest_Registration{Registration: &pb.RegistrationStepData{Email: email}}}); err != nil {
		t.Fatal(err)
	}
	challenge, err := client.StartAuthenticationStep(ctx, &pb.StartAuthenticationStepRequest{Flow: flow, Type: "emailVerification"})
	if err != nil {
		t.Fatal(err)
	}
	var code string
	if err = db.QueryRowContext(ctx, "SELECT body->>'code' FROM outbox WHERE type='mail.send.v1' AND body->>'to'=$1", email).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatal("outbox did not contain a six-digit registration code")
	}
	attempt, err := client.CompleteAuthenticationStep(ctx, &pb.CompleteAuthenticationStepRequest{Step: &pb.AuthenticationStepContext{Flow: flow, StepId: challenge.Id}, Proof: &pb.CompleteAuthenticationStepRequest_Email{Email: &pb.CodeChallengeProof{Code: code}}})
	if err != nil {
		t.Fatal(err)
	}
	if attempt.Authentication.Status != "pending" || attempt.Authentication.ConfirmationToken != "" {
		t.Fatal("email proof prematurely completed registration")
	}
	password, err := client.StartAuthenticationStep(ctx, &pb.StartAuthenticationStepRequest{Flow: flow, Type: "passwordSetup"})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err = client.CompleteAuthenticationStep(ctx, &pb.CompleteAuthenticationStepRequest{Step: &pb.AuthenticationStepContext{Flow: flow, StepId: password.Id}, Proof: &pb.CompleteAuthenticationStepRequest_PasswordSetup{PasswordSetup: &pb.PasswordSetupStepData{Password: "runtime-test-password"}}})
	if err != nil {
		t.Fatal(err)
	}
	if attempt.Authentication.Status != "completed" || attempt.Authentication.ConfirmationToken == "" {
		t.Fatal("password setup did not finish signup")
	}
	token, err := client.CreateSession(ctx, &pb.CreateAuthenticatedSessionRequest{AuthenticationToken: attempt.Authentication.ConfirmationToken, Ip: "127.0.0.1", UserAgent: "ChefBook runtime test"})
	if err != nil {
		t.Fatal(err)
	}
	if token.SessionId <= 0 || token.RefreshToken == "" {
		t.Fatal("missing session identity")
	}
	public, err := legacy.GetAccessTokenPublicKey(ctx, &pb.GetAccessTokenPublicKeyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	parser, err := access.NewParserByRawKey(public.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := parser.Parse(token.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if payload.SessionID != token.SessionId || payload.UserId.String() != token.UserId {
		t.Fatal("signed JWT lost account/session binding")
	}
	who := &pb.AuthPrincipal{AccountId: token.UserId, SessionId: token.SessionId}
	if _, err = client.ValidateSession(ctx, who); err != nil {
		t.Fatal(err)
	}
	info, err := legacy.GetAuthInfo(ctx, &pb.GetAuthInfoRequest{Id: token.UserId})
	if err != nil || info.Email != email || !info.IsActivated {
		t.Fatalf("legacy account read failed: %v", err)
	}
	// Running the initial installer against a populated schema must refuse, leaving
	// both the schema and confirmed account intact.
	if err = schema.Initialize(ctx, db); err == nil {
		t.Fatal("initial installer accepted populated schema")
	}
	if err = schema.Check(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM accounts WHERE account_id=$1", token.UserId).Scan(&accounts); err != nil || accounts != 1 {
		t.Fatal("second initialization modified account data")
	}
	rotated, err := client.RefreshSession(ctx, &pb.RotateSessionRequest{SessionId: token.SessionId, RefreshToken: token.RefreshToken, Ip: "127.0.0.1", UserAgent: "ChefBook runtime test"})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RefreshToken == token.RefreshToken || rotated.SessionId != token.SessionId {
		t.Fatal("refresh did not rotate the same session")
	}
	_, err = client.RefreshSession(ctx, &pb.RotateSessionRequest{SessionId: token.SessionId, RefreshToken: token.RefreshToken, Ip: "127.0.0.1"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid refresh returned %v", status.Code(err))
	}
	found := false
	for _, detail := range status.Convert(err).Details() {
		if d, ok := detail.(*errdetails.ErrorInfo); ok && d.Reason == "invalid_refresh_token" {
			found = true
		}
	}
	if !found {
		t.Fatal("refresh failure lost machine-readable ErrorInfo")
	}
	if _, err = client.ValidateSession(ctx, who); err != nil {
		t.Fatal("invalid old refresh destroyed valid rotated session")
	}
	if _, err = client.RevokeSessions(ctx, &pb.RevokeAuthSessionRequest{Principal: who, SessionId: &token.SessionId}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.ValidateSession(ctx, who); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked session validation code=%v", status.Code(err))
	}
	if _, err = legacy.SignIn(ctx, &pb.SignInRequest{Email: email, Password: "runtime-test-password"}); status.Code(err) != codes.Unimplemented {
		t.Fatal("legacy sign-in bypass available")
	}
}
