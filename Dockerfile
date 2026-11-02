FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/access-gateway ./cmd/access-gateway

FROM alpine:latest
COPY --from=build /out/access-gateway /access-gateway
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s CMD wget -q -O /dev/null http://127.0.0.1:${SERVICE_PORT:-8080}/readyz || exit 1
ENTRYPOINT ["/access-gateway"]
