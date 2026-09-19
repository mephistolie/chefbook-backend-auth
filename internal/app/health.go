package app

import (
	"context"
	"database/sql"
	authpb "github.com/mephistolie/chefbook-backend-auth/api/proto/implementation/v1"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"time"
)

func monitorHealthChecking(ctx context.Context, db *sql.DB, server *health.Server) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status := healthpb.HealthCheckResponse_SERVING
			check, cancel := context.WithTimeout(ctx, 5*time.Second)
			e := db.PingContext(check)
			cancel()
			if e != nil {
				status = healthpb.HealthCheckResponse_NOT_SERVING
				events.PostgresHealthCheckFailed(ctx, e)
			}
			setHealthStatus(server, status)
		}
	}
}
func setHealthStatus(server *health.Server, status healthpb.HealthCheckResponse_ServingStatus) {
	for _, name := range []string{"", authpb.AuthService_ServiceDesc.ServiceName, authpb.AuthenticationService_ServiceDesc.ServiceName} {
		server.SetServingStatus(name, status)
	}
}
