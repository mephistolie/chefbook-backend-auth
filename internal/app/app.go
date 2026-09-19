package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	authpb "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/authentication"
	"github.com/mephistolie/chefbook-backend-auth/internal/authentication/provider"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-auth/internal/outbox"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/authenticationgrpc"
	"github.com/mephistolie/chefbook-backend-auth/pkg/passkey"
	"github.com/mephistolie/chefbook-backend-auth/schema"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/tokens"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var events logging.Events

func split(value *string) []string {
	out := []string{}
	if value == nil {
		return out
	}
	for _, v := range strings.Split(*value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
func text(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func stableSecrets(c config.Security) (authentication.Secrets, error) {
	mac, e := base64.StdEncoding.DecodeString(text(c.HMACKey))
	if e != nil {
		return authentication.Secrets{}, errors.New("invalid auth HMAC key encoding")
	}
	encryption, e := base64.StdEncoding.DecodeString(text(c.EncryptionKey))
	if e != nil {
		return authentication.Secrets{}, errors.New("invalid auth encryption key encoding")
	}
	return authentication.NewSecrets(mac, encryption)
}
func configureEngine(db *sql.DB, cfg *config.Config) (*authentication.Engine, *tokens.Manager, error) {
	secrets, e := stableSecrets(cfg.Security)
	if e != nil {
		return nil, nil, e
	}
	var issuer *tokens.Manager
	if text(cfg.Auth.AccessTokenSigningKey) != "" {
		issuer, e = tokens.NewManagerByRawKey([]byte(*cfg.Auth.AccessTokenSigningKey))
	} else {
		if *cfg.Environment == config.EnvProd {
			return nil, nil, errors.New("production signing key is required")
		}
		var key *rsa.PrivateKey
		key, e = rsa.GenerateKey(rand.Reader, 2048)
		if e == nil {
			issuer = tokens.NewManagerByKey(key)
		}
	}
	if e != nil {
		return nil, nil, errors.New("cannot initialize signing key")
	}
	engine := authentication.New(db, secrets, authentication.OutboxMail{})
	engine.BcryptCost = *cfg.Auth.SaltCost
	engine.Providers = map[string]authentication.Provider{}
	if text(cfg.OAuth.Google.ClientId) != "" {
		engine.Providers["google"] = provider.Google{ClientID: *cfg.OAuth.Google.ClientId, ClientSecret: text(cfg.OAuth.Google.ClientSecret)}
	}
	if text(cfg.OAuth.Vk.ClientId) != "" && text(cfg.OAuth.Vk.ClientSecret) != "" {
		engine.Providers["vk"] = provider.VK{ClientID: *cfg.OAuth.Vk.ClientId, ClientSecret: *cfg.OAuth.Vk.ClientSecret}
	}
	engine.OAuthRedirects = split(cfg.Security.OAuthRedirects)
	for _, redirect := range engine.OAuthRedirects {
		u, err := url.Parse(redirect)
		if err != nil || u.Scheme == "" || u.User != nil || u.Fragment != "" {
			return nil, nil, errors.New("invalid OAuth redirect allowlist")
		}
	}
	if text(cfg.Security.RPID) != "" {
		engine.Passkeys, e = passkey.New(passkey.Config{RPID: *cfg.Security.RPID, Origins: split(cfg.Security.Origins), OpaqueOrigins: split(cfg.Security.OpaqueOrigins)})
		if e != nil {
			return nil, nil, e
		}
	}
	for _, raw := range []string{text(cfg.Security.PasswordResetURL), text(cfg.Security.EmailChangeURL)} {
		if raw != "" {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
				return nil, nil, errors.New("invalid HTTPS confirmation URL")
			}
		}
	}
	return engine, issuer, nil
}

func Run(cfg *config.Config) {
	log.InitWithService("auth", *cfg.LogsPath, *cfg.Environment == config.EnvDev)
	cfg.Print()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	db, e := sql.Open("pgx", config.DatabaseURL(cfg.Database))
	if e != nil {
		events.StartupFailed(ctx, "connect_postgres", errors.New("database configuration failed"))
		return
	}
	defer db.Close()
	// Leave room for initialization and administrative checks (service limit: 15).
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	startup, stopStartup := context.WithTimeout(ctx, 15*time.Second)
	e = db.PingContext(startup)
	if e == nil {
		e = schema.Check(startup, db)
	}
	stopStartup()
	if e != nil {
		events.StartupFailed(ctx, "check_initial_schema", errors.New("database unavailable or initial auth schema missing"))
		return
	}
	engine, issuer, e := configureEngine(db, cfg)
	if e != nil {
		events.StartupFailed(ctx, "configure_authentication", e)
		return
	}
	publicDER := x509.MarshalPKCS1PublicKey(issuer.GetAccessPublicKey())
	server := grpc.NewServer(grpc.ChainUnaryInterceptor(log.UnaryServerInterceptor()), grpc.MaxRecvMsgSize(128*1024))
	authpb.RegisterAuthenticationServiceServer(server, &authenticationgrpc.Server{Engine: engine, Issuer: issuer, AccessTTL: *cfg.Auth.Ttl.AccessToken, RefreshTTL: *cfg.Auth.Ttl.RefreshToken, DeletionDelay: *cfg.ProfileDeletion.Offset, PasswordResetURL: text(cfg.Security.PasswordResetURL), EmailChangeURL: text(cfg.Security.EmailChangeURL)})
	authpb.RegisterAuthServiceServer(server, &authenticationgrpc.LegacyReads{DB: db, PublicKey: publicDER})
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)
	setHealthStatus(healthServer, healthpb.HealthCheckResponse_SERVING)
	lis, e := net.Listen("tcp", fmt.Sprintf(":%d", *cfg.Port))
	if e != nil {
		events.StartupFailed(ctx, "listen_grpc", e)
		return
	}
	defer lis.Close()
	workers := sync.WaitGroup{}
	workers.Add(1)
	go func() { defer workers.Done(); monitorHealthChecking(ctx, db, healthServer) }()
	if text(cfg.Amqp.Host) != "" {
		broker := url.URL{Scheme: "amqp", Host: net.JoinHostPort(*cfg.Amqp.Host, strconv.Itoa(*cfg.Amqp.Port)), User: url.UserPassword(*cfg.Amqp.User, *cfg.Amqp.Password), Path: "/" + *cfg.Amqp.VHost}
		workers.Add(1)
		go func() { defer workers.Done(); outbox.Worker{DB: db, URL: broker.String()}.Run(ctx) }()
	}
	workers.Add(1)
	go func() { defer workers.Done(); runDeletions(ctx, engine, *cfg.ProfileDeletion.CheckInterval) }()
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				call, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := engine.Cleanup(call)
				cancel()
				if err != nil {
					events.TemporaryStateCleanupFailed(ctx, err)
				}
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- server.Serve(lis) }()
	events.GRPCServerStarted(ctx)
	select {
	case <-ctx.Done():
	case err := <-done:
		if err != nil {
			events.GRPCServerFailed(ctx, err)
		}
		cancel()
	}
	healthServer.Shutdown()
	cancel()
	stopped := make(chan struct{})
	go func() { server.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		server.Stop()
	}
	workers.Wait()
}
func runDeletions(ctx context.Context, e *authentication.Engine, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		for ctx.Err() == nil {
			call, cancel := context.WithTimeout(ctx, 10*time.Second)
			removed, err := e.DeleteDueAccount(call)
			cancel()
			if err != nil {
				events.AccountDeletionBatchFailed(ctx, err)
				break
			}
			if !removed {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
