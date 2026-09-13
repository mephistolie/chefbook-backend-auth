package app

import (
	"context"
	"github.com/jmoiron/sqlx"
	authpb "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"time"
)

func monitorHealthChecking(db *sqlx.DB, healthServer *health.Server) {
	for {
		status := healthpb.HealthCheckResponse_SERVING
		if err := db.Ping(); err != nil {
			status = healthpb.HealthCheckResponse_NOT_SERVING
			events.PostgresHealthCheckFailed(context.Background(), err)
		}
		setHealthStatus(healthServer, status)
		time.Sleep(1 * time.Minute)
	}
}

func setHealthStatus(healthServer *health.Server, status healthpb.HealthCheckResponse_ServingStatus) {
	healthServer.SetServingStatus("", status)
	healthServer.SetServingStatus(authpb.AuthService_ServiceDesc.ServiceName, status)
}
