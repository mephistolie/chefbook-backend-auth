package app

import (
	"context"
	"fmt"
	authpb "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/app/daemon"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
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

func Run(cfg *config.Config) {
	log.InitWithService("auth", *cfg.LogsPath, *cfg.Environment == config.EnvDev)
	cfg.Print()

	ctx := context.Background()

	db, err := postgres.Connect(cfg.Database)
	if err != nil {
		log.LogFatal(ctx, log.Event{
			Event:     "app.startup.failed",
			Message:   "service startup failed",
			Component: "app",
		}, err)
		return
	}

	repository := postgres.NewRepository(db, *cfg.ProfileDeletion.Offset)

	grpcRepository, err := grpcRepo.NewRepository(cfg)
	if err != nil {
		log.LogFatal(ctx, log.Event{
			Event:     "app.startup.failed",
			Message:   "service startup failed",
			Component: "app",
		}, err)
		return
	}

	var mq *amqp.Repository = nil
	if len(*cfg.Amqp.Host) > 0 {
		mq, err = amqp.NewRepository(cfg.Amqp, repository)
		if err != nil {
			log.LogFatal(ctx, log.Event{
				Event:     "app.startup.failed",
				Message:   "service startup failed",
				Component: "app",
			}, err)
			return
		}
		if err = mq.Start(); err != nil {
			log.LogFatal(ctx, log.Event{
				Event:     "app.startup.failed",
				Message:   "service startup failed",
				Component: "app",
			}, err)
			return
		}
		log.Log(ctx, log.Event{
			Event:     "mq.server.initialized",
			Message:   "mq server initialized",
			Component: log.ComponentAMQP,
		})
	}

	authService, err := service.New(ctx, cfg, repository, grpcRepository, mq)
	if err != nil {
		log.LogFatal(ctx, log.Event{
			Event:     "app.startup.failed",
			Message:   "service startup failed",
			Component: "app",
		}, err)
		return
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *cfg.Port))
	if err != nil {
		log.LogFatal(ctx, log.Event{
			Event:     "app.startup.failed",
			Message:   "service startup failed",
			Component: "app",
		}, err)
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

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.LogError(ctx, log.Event{
				Event:     "grpc.server.failed",
				Message:   "error occurred while running grpc server",
				Component: log.ComponentGRPC,
			}, err)
		} else {
			log.Log(ctx, log.Event{
				Event:     "grpc.server.started",
				Message:   "grpc server started",
				Component: log.ComponentGRPC,
			})
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
