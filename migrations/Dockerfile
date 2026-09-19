# Empty-database initializer. Build from the chefbook-backend workspace root.
FROM golang:1.26.2-alpine AS builder
WORKDIR /workspace/services/auth
COPY services/auth ./
COPY common/tokens /workspace/common/tokens
COPY common/firebase /workspace/common/firebase
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/auth-initialize ./cmd/migrations

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 auth
COPY --from=builder /out/auth-initialize /usr/local/bin/auth-initialize
USER auth
# Requires explicit --initialize; refuses a nonempty schema.
ENTRYPOINT ["/usr/local/bin/auth-initialize"]
