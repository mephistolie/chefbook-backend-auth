FROM golang:alpine as builder

WORKDIR /build

COPY go.mod go.sum ./
COPY api /api
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /main cmd/app/main.go

FROM alpine:latest

COPY --from=builder main /bin/main
COPY --from=builder build/assets /assets
ENTRYPOINT ["/bin/main"]
