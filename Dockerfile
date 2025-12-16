FROM golang:alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/access-gateway ./cmd/access-gateway

FROM alpine:latest
COPY --from=build /out/access-gateway /access-gateway
EXPOSE 8080
ENTRYPOINT ["/access-gateway"]