FROM golang:alpine as builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o /main cmd/migrations/main.go

FROM alpine:latest

COPY --from=builder main /bin/main
ENTRYPOINT ["/bin/main"]
