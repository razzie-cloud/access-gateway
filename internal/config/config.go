package config

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/alexflint/go-arg"
)

type Config struct {
	ServicePort          int    `arg:"--port,env:SERVICE_PORT" default:"8080"`
	Origin               string `arg:"--origin,env:ORIGIN" default:"http://localhost:8080"`
	RPID                 string `arg:"--rp-id,env:RP_ID" default:"localhost"`
	RPName               string `arg:"--rp-name,env:RP_NAME" default:"Minimal WebAuthn"`
	ForwardAuthOrigins   string `arg:"--forward-auth-origins,env:FORWARD_AUTH_ORIGINS" help:"Comma-separated exact public app origins allowed to use forward auth"`
	PostgresURI          string `arg:"--postgres-uri,env:POSTGRES_URI"`
	PostgresURIFrom      string `arg:"--postgres-uri-from,env:POSTGRES_URI_FROM"`
	PostgresPasswordFile string `arg:"--postgres-password-file,env:POSTGRES_PASSWORD_FILE"`
	RedisURI             string `arg:"--redis-uri,env:REDIS_URI"`
	RedisURIFrom         string `arg:"--redis-uri-from,env:REDIS_URI_FROM"`
	RedisPasswordFile    string `arg:"--redis-password-file,env:REDIS_PASSWORD_FILE"`
}

func Load() (*Config, error) {
	var cfg Config
	if err := arg.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.PostgresURIFrom != "" {
		uri, err := http.Get(cfg.PostgresURIFrom)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch Postgres URI from %s: %w", cfg.PostgresURIFrom, err)
		}
		defer uri.Body.Close()
		body, err := io.ReadAll(uri.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read Postgres URI response body: %w", err)
		}
		cfg.PostgresURI = string(body)
	}
	if cfg.PostgresURI == "" {
		return nil, fmt.Errorf("Postgres URI is required: set POSTGRES_URI or POSTGRES_URI_FROM")
	}
	if cfg.PostgresURI != "" && cfg.PostgresPasswordFile != "" {
		pwd, err := os.ReadFile(cfg.PostgresPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read Postgres password file: %w", err)
		}
		uri, err := url.Parse(cfg.PostgresURI)
		if err != nil {
			return nil, fmt.Errorf("invalid Postgres URI: %w", err)
		}
		uri.User = url.UserPassword(uri.User.Username(), string(pwd))
		cfg.PostgresURI = uri.String()
	}

	if cfg.RedisURIFrom != "" {
		uri, err := http.Get(cfg.RedisURIFrom)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch Redis URI from %s: %w", cfg.RedisURIFrom, err)
		}
		defer uri.Body.Close()
		body, err := io.ReadAll(uri.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read Redis URI response body: %w", err)
		}
		cfg.RedisURI = string(body)
	}
	if cfg.RedisURI != "" && cfg.RedisPasswordFile != "" {
		pwd, err := os.ReadFile(cfg.RedisPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read Redis password file: %w", err)
		}
		uri, err := url.Parse(cfg.RedisURI)
		if err != nil {
			return nil, fmt.Errorf("invalid Redis URI: %w", err)
		}
		username := ""
		if uri.User != nil {
			username = uri.User.Username()
		}
		uri.User = url.UserPassword(username, strings.TrimRight(string(pwd), "\r\n"))
		cfg.RedisURI = uri.String()
	}
	if cfg.RedisURI == "" {
		return nil, fmt.Errorf("Redis URI is required: set REDIS_URI or REDIS_URI_FROM")
	}

	return &cfg, nil
}
