package app

import (
	"context"
	"fmt"
	authpb "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/repository/amqp"
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
	log.Init(*cfg.LogsPath, *cfg.Environment == config.EnvDev)
	cfg.Print()

	db, err := postgres.Connect(cfg.Database)
	if err != nil {
		log.Fatal(err)
		return
	}

	repository := postgres.NewRepository(db)

	var mq *amqp.Repository = nil
	if len(*cfg.Amqp.Host) > 0 {
		mq, err = amqp.NewRepository(cfg.Amqp, repository)
		if err != nil {
			log.Fatal(err)
			return
		}
		if err = mq.Start(); err != nil {
			log.Fatal(err)
			return
		}
		log.Info("MQ server initialized")
	}

	authService, err := service.New(cfg, repository, mq)
	if err != nil {
		log.Fatal(err)
		return
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *cfg.Port))
	if err != nil {
		log.Fatal(err)
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
			log.Errorf("error occurred while running http server: %s\n", err.Error())
		} else {
			log.Info("gRPC server started")
		}
	}()

	wait := shutdown.Graceful(context.Background(), 5*time.Second, map[string]shutdown.Operation{
		"grpc-server": func(ctx context.Context) error {
			grpcServer.GracefulStop()
			return nil
		},
		"database": func(ctx context.Context) error {
			return db.Close()
		},
		"mq": func(ctx context.Context) error {
			if mq == nil {
				return nil
			}
			return mq.Stop()
		},
	})
	<-wait
}
