package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-rel/postgres"
	"github.com/go-rel/rel"
	"github.com/go-webauthn/webauthn/webauthn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/razzie-cloud/access-gateway/internal/db"
)

type Config struct {
	ListenAddr  string
	DatabaseURL string

	Origin string
	RPID   string
	RPName string
}

type Server struct {
	cfg Config

	db   *sql.DB
	repo rel.Repository
	wa   *webauthn.WebAuthn

	mem *MemorySessions

	mux *http.ServeMux
}

func NewServer(cfg Config) (*Server, error) {
	sqlDB, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	if err := db.RunMigrations(sqlDB); err != nil {
		return nil, err
	}

	adapter := postgres.New(sqlDB)
	repo := rel.New(adapter)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPName,
		RPID:          cfg.RPID,
		RPOrigins:     []string{cfg.Origin},
	})
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:  cfg,
		db:   sqlDB,
		repo: repo,
		wa:   wa,
		mem:  NewMemorySessions(30 * time.Minute),
		mux:  http.NewServeMux(),
	}
	s.routes()

	if err := s.ensureBootstrapTokenIfNoUsers(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Server) ListenAndServe() error {
	return http.ListenAndServe(s.cfg.ListenAddr, s.handler())
}

func (s *Server) ensureBootstrapTokenIfNoUsers(ctx context.Context) error {
	n, err := s.countUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	hash, err := s.getAppState(ctx, "bootstrap_token_sha256")
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if hash != "" {
		return nil
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	tokenHex := hex.EncodeToString(token)

	sum := sha256.Sum256([]byte(tokenHex))
	if err := s.setAppState(ctx, "bootstrap_token_sha256", hex.EncodeToString(sum[:])); err != nil {
		return err
	}

	log.Printf("BOOTSTRAP TOKEN (one-time, first user only): %s", tokenHex)
	return nil
}
