package app

import (
	"context"
	"fmt"
	authpb "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/app/daemon"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/logging"
	"github.com/mephistolie/chefbook-backend-auth/internal/repository/amqp"
	grpcRepo "github.com/mephistolie/chefbook-backend-auth/internal/repository/grpc"
	"github.com/mephistolie/chefbook-backend-auth/internal/repository/postgres"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/dependencies/service"
	auth "github.com/mephistolie/chefbook-backend-auth/internal/transport/grpc"
	"github.com/mephistolie/chefbook-backend-common/log"
	"github.com/mephistolie/chefbook-backend-common/shutdown"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"net"
	"time"
)

var events logging.Events

func Run(cfg *config.Config) {
	log.InitWithService("auth", *cfg.LogsPath, *cfg.Environment == config.EnvDev)
	cfg.Print()

	ctx := context.Background()

	db, err := postgres.Connect(cfg.Database)
	if err != nil {
		events.StartupFailed(ctx, "connect_postgres", err)
		return
	}

	repository := postgres.NewRepository(db, *cfg.ProfileDeletion.Offset)

	grpcRepository, err := grpcRepo.NewRepository(cfg)
	if err != nil {
		events.StartupFailed(ctx, "initialize_grpc_repository", err)
		return
	}

	var mq *amqp.Repository = nil
	if len(*cfg.Amqp.Host) > 0 {
		mq, err = amqp.NewRepository(cfg.Amqp, repository)
		if err != nil {
			events.StartupFailed(ctx, "initialize_mq_server", err)
			return
		}
		if err = mq.Start(); err != nil {
			events.StartupFailed(ctx, "start_mq_server", err)
			return
		}
		events.MQServerInitialized(ctx)
	}

	authService, err := service.New(ctx, cfg, repository, grpcRepository, mq)
	if err != nil {
		events.StartupFailed(ctx, "initialize_service", err)
		return
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *cfg.Port))
	if err != nil {
		events.StartupFailed(ctx, "listen_grpc", err)
		return
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			log.UnaryServerInterceptor(),
		),
	)

	healthServer := health.NewServer()
	authServer := auth.NewServer(*authService)

	go monitorHealthChecking(db, healthServer)

	authpb.RegisterAuthServiceServer(grpcServer, authServer)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	events.GRPCServerStarted(ctx)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			events.GRPCServerFailed(ctx, err)
		}
	}()

	daemonService := daemon.New(authService.ProfileDeletion, cfg.ProfileDeletion)
	go daemonService.Start()

	wait := shutdown.Graceful(ctx, 5*time.Second, map[string]shutdown.Operation{
		"grpc-server": func(ctx context.Context) error {
			grpcServer.GracefulStop()
			return nil
		},
		"database": func(ctx context.Context) error {
			return db.Close()
		},
		"services": func(ctx context.Context) error {
			return grpcRepository.Stop()
		},
		"mq": func(ctx context.Context) error {
			if mq == nil {
				return nil
			}
			return mq.Stop()
		},
		"daemon": func(ctx context.Context) error {
			daemonService.Stop()
			return nil
		},
	})
	<-wait
}
