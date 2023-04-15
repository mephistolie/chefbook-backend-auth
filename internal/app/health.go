package app

import (
	"github.com/jmoiron/sqlx"
	authpb "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"github.com/mephistolie/chefbook-backend-common/log"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"time"
)

func monitorHealthChecking(db *sqlx.DB, healthServer *health.Server) {
	for {
		status := healthpb.HealthCheckResponse_SERVING
		if db.Ping() != nil {
			status = healthpb.HealthCheckResponse_NOT_SERVING
			log.Error("database is unavailable")
		}
		setHealthStatus(healthServer, status)
		time.Sleep(1 * time.Minute)
	}
}

func setHealthStatus(healthServer *health.Server, status healthpb.HealthCheckResponse_ServingStatus) {
	healthServer.SetServingStatus("", status)
	healthServer.SetServingStatus(authpb.AuthService_ServiceDesc.ServiceName, status)
}
