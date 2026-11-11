package config

import (
	"context"
	"fmt"
	"github.com/razzie-cloud/access-gateway/internal/brokerdiscovery"
	"net/url"
	"os"
	"strings"

	"github.com/alexflint/go-arg"
)

type Config struct {
	BrokerTokenFile      string `arg:"--broker-token-file,env:BROKER_TOKEN_FILE"`
	BrokerCAFile         string `arg:"--broker-ca-file,env:BROKER_CA_FILE"`
	LandingOrigin        string `arg:"--landing-origin,env:LANDING_ORIGIN" default:"https://razzie.cloud"`
	ServicePort          int    `arg:"--port,env:SERVICE_PORT" default:"8080"`
	Origin               string `arg:"--origin,env:ORIGIN" default:"http://localhost:8080"`
	RPID                 string `arg:"--rp-id,env:RP_ID" default:"localhost"`
	RPName               string `arg:"--rp-name,env:RP_NAME" default:"Minimal WebAuthn"`
	ForwardAuthOrigins   string `arg:"--forward-auth-origins,env:FORWARD_AUTH_ORIGINS" help:"Comma-separated exact public app origins allowed to use forward auth"`
	TrustedProxies       string `arg:"--trusted-proxies,env:TRUSTED_PROXIES" help:"Comma-separated proxy IPs/CIDRs trusted to supply X-Forwarded-For"`
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
		return nil, fmt.Errorf("invalid command-line configuration")
	}

	landing, landingErr := url.Parse(cfg.LandingOrigin)
	if landingErr != nil || landing.Hostname() == "" || (landing.Scheme != "http" && landing.Scheme != "https") || landing.User != nil || landing.Path != "" || landing.RawQuery != "" || landing.ForceQuery || landing.Fragment != "" {
		return nil, fmt.Errorf("LANDING_ORIGIN must be an exact http(s) origin")
	}
	if cfg.BrokerTokenFile != "" && cfg.PostgresURIFrom == "" && cfg.RedisURIFrom == "" {
		return nil, fmt.Errorf("BROKER_TOKEN_FILE requires discovery")
	}
	if cfg.PostgresURIFrom != "" {
		value, err := brokerdiscovery.Fetch(context.Background(), cfg.PostgresURIFrom, brokerdiscovery.Options{TokenFile: cfg.BrokerTokenFile, CAFile: cfg.BrokerCAFile})
		if err != nil {
			return nil, err
		}
		cfg.PostgresURI = value
	}

	if cfg.PostgresURI != "" {
		u, e := url.Parse(cfg.PostgresURI)
		if e != nil || u.Host == "" || u.User == nil || u.Path == "" || u.Fragment != "" || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
			return nil, fmt.Errorf("invalid Postgres URI")
		}
	}
	if cfg.PostgresURI == "" {
		return nil, fmt.Errorf("Postgres URI is required: set POSTGRES_URI or POSTGRES_URI_FROM")
	}
	if cfg.PostgresURI != "" && cfg.PostgresPasswordFile != "" {
		pwd, err := os.ReadFile(cfg.PostgresPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read Postgres password file")
		}
		uri, err := url.Parse(cfg.PostgresURI)
		if err != nil || uri.Host == "" || uri.User == nil || (uri.Scheme != "postgres" && uri.Scheme != "postgresql") {
			return nil, fmt.Errorf("invalid Postgres URI")
		}
		uri.User = url.UserPassword(uri.User.Username(), string(pwd))
		cfg.PostgresURI = uri.String()
	}

	if cfg.RedisURIFrom != "" {
		value, err := brokerdiscovery.Fetch(context.Background(), cfg.RedisURIFrom, brokerdiscovery.Options{TokenFile: cfg.BrokerTokenFile, CAFile: cfg.BrokerCAFile})
		if err != nil {
			return nil, err
		}
		cfg.RedisURI = value
	}

	if cfg.RedisURI != "" {
		u, e := url.Parse(cfg.RedisURI)
		if e != nil || u.Host == "" || u.Fragment != "" || (u.Scheme != "redis" && u.Scheme != "rediss") {
			return nil, fmt.Errorf("invalid Redis URI")
		}
	}
	if cfg.RedisURI != "" && cfg.RedisPasswordFile != "" {
		pwd, err := os.ReadFile(cfg.RedisPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read Redis password file")
		}
		uri, err := url.Parse(cfg.RedisURI)
		if err != nil {
			return nil, fmt.Errorf("invalid Redis URI")
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
