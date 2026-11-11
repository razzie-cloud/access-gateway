package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/razzie-cloud/access-gateway/internal/app"
	"github.com/razzie-cloud/access-gateway/internal/config"
	"github.com/razzie-cloud/access-gateway/internal/logging"
)

func main() {
	if err := logging.Setup("access-gateway"); err != nil {
		slog.Error(err.Error(), "event", "config.invalid", "field", "LOG_LEVEL")
		os.Exit(1)
	}
	if err := run(); err != nil {
		slog.Error("Service failed", append([]any{"event", "server.failed"}, logging.ErrorAttrs(err)...)...)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return logging.Wrap("config", err)
	}

	addr := fmt.Sprintf(":%d", cfg.ServicePort)
	s, err := app.NewServer(app.Config{
		ListenAddr:         addr,
		LandingOrigin:      cfg.LandingOrigin,
		DatabaseURL:        cfg.PostgresURI,
		RedisURL:           cfg.RedisURI,
		Origin:             cfg.Origin,
		RPID:               cfg.RPID,
		RPName:             cfg.RPName,
		ForwardAuthOrigins: strings.FieldsFunc(cfg.ForwardAuthOrigins, func(r rune) bool { return r == ',' }),
		TrustedProxies:     strings.FieldsFunc(cfg.TrustedProxies, func(r rune) bool { return r == ',' }),
	})
	if err != nil {
		return err
	}
	defer s.Close()

	slog.Info("Server listening", "event", "server.listening", "address", addr)
	if err := s.ListenAndServe(); err != nil {
		return logging.Wrap("serve", err)
	}
	return nil
}
