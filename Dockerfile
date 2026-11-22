FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/access-gateway ./cmd/access-gateway

FROM gcr.io/distroless/static-debian13:latest
COPY --from=build /out/access-gateway /access-gateway
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s CMD ["/access-gateway", "healthcheck"]
ENTRYPOINT ["/access-gateway"]
