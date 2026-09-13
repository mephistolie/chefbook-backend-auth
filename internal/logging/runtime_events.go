package logging

import (
	"context"

	"github.com/mephistolie/chefbook-backend-common/log"
)

func (Events) ConfigLoaded(ctx context.Context) {
	log.Log(ctx, log.Event{
		Event:     "config.loaded",
		Message:   "service configuration loaded",
		Component: "config",
	})
}

func (Events) StartupFailed(ctx context.Context, operation string, err error) {
	log.LogFatal(ctx, log.Event{
		Event:     "app.startup.failed",
		Message:   "service startup failed",
		Component: "app",
		Operation: operation,
		ErrorType: safeErrorType(err, "startup_error"),
	}, nil)
}

func (Events) MQServerInitialized(ctx context.Context) {
	log.Log(ctx, log.Event{
		Event:     "mq.server.initialized",
		Message:   "MQ server initialized",
		Component: log.ComponentAMQP,
	})
}

func (Events) GRPCServerStarted(ctx context.Context) {
	log.Log(ctx, log.Event{
		Event:     "grpc.server.started",
		Message:   "gRPC server started",
		Component: log.ComponentGRPC,
		Operation: "serve",
	})
}

func (Events) GRPCServerFailed(ctx context.Context, err error) {
	log.LogError(ctx, log.Event{
		Event:     "grpc.server.failed",
		Message:   "gRPC server stopped with an error",
		Component: log.ComponentGRPC,
		Operation: "serve",
	}, err)
}

func (Events) PostgresHealthCheckFailed(ctx context.Context, err error) {
	log.LogWarn(ctx, log.Event{
		Event:     "postgres.health_check.failed",
		Message:   "database is unavailable",
		Component: log.ComponentPostgres,
		Operation: "ping",
		ErrorType: safeErrorType(err, "postgres_error"),
	})
}
