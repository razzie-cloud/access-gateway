package app

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-rel/postgres"
	"github.com/go-rel/rel"
	"github.com/go-webauthn/webauthn/webauthn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/razzie-cloud/access-gateway/internal/db"
	"github.com/razzie-cloud/access-gateway/internal/health"
	"github.com/razzie-cloud/access-gateway/internal/logging"
)

type Config struct {
	LandingOrigin string
	ListenAddr    string
	DatabaseURL   string
	RedisURL      string

	Origin string
	RPID   string
	RPName string

	// Exact public app origins permitted to use forward authentication.
	ForwardAuthOrigins []string
	TrustedProxies     []string
}

type Server struct {
	cfg Config

	db          *sql.DB
	repo        rel.Repository
	wa          *webauthn.WebAuthn
	loginSecret []byte

	sessions       sessionStore
	limits         *requestLimits
	trustedProxies []netip.Prefix

	mux        *http.ServeMux
	health     *health.Monitor
	stopHealth func()
}

func NewServer(cfg Config) (*Server, error) {
	if err := validateForwardAuthConfig(cfg); err != nil {
		return nil, logging.Wrap("forward_auth_config", err)
	}
	proxies, err := parseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return nil, logging.Wrap("trusted_proxy_config", err)
	}
	sessions, err := newRedisSessions(cfg.RedisURL, cfg.Origin)
	if err != nil {
		return nil, logging.Wrap("redis_connect", err)
	}
	sqlDB, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		_ = sessions.Close()
		return nil, logging.Wrap("postgres_open", err)
	}
	initialized := false
	defer func() {
		if !initialized {
			_ = sessions.Close()
			_ = sqlDB.Close()
		}
	}()

	if err := db.RunMigrations(sqlDB); err != nil {
		return nil, logging.Wrap("migrations", err)
	}

	adapter := postgres.New(sqlDB)
	repo := rel.New(adapter)
	repo.Instrumentation(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPName,
		RPID:          cfg.RPID,
		RPOrigins:     []string{cfg.Origin},
	})
	if err != nil {
		return nil, logging.Wrap("webauthn_init", err)
	}

	s := &Server{
		cfg:            cfg,
		db:             sqlDB,
		repo:           repo,
		wa:             wa,
		sessions:       sessions,
		trustedProxies: proxies,
		mux:            http.NewServeMux(),
	}
	if err := s.ensureLoginSecret(ctx); err != nil {
		return nil, logging.Wrap("login_secret", err)
	}
	s.routes()

	if err := s.ensureBootstrapTokenIfNoUsers(ctx); err != nil {
		return nil, logging.Wrap("bootstrap", err)
	}

	s.health = health.New(
		health.Check{Name: "postgres", Ping: sqlDB.PingContext},
		health.Check{Name: "redis", Ping: func(ctx context.Context) error { return sessions.client.Ping(ctx).Err() }},
	)
	s.stopHealth = s.health.Start(context.Background())
	initialized = true
	return s, nil
}

func (s *Server) Close() error {
	if s.stopHealth != nil {
		s.stopHealth()
	}
	return errors.Join(s.sessions.Close(), s.db.Close())
}

func (s *Server) ListenAndServe() error {
	server := &http.Server{Addr: s.cfg.ListenAddr, Handler: s.handler(), ErrorLog: logging.ServerLogger()}
	return server.ListenAndServe()
}
