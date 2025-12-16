package main

import (
	"log"
	"os"

	"github.com/razzie-cloud/access-gateway/internal/app"
)

func main() {
	cfg := app.Config{
		ListenAddr:  env("LISTEN_ADDR", ":8080"),
		DatabaseURL: mustEnv("DATABASE_URL"),
		Origin:      env("ORIGIN", "http://localhost:8080"),
		RPID:        env("RP_ID", "localhost"),
		RPName:      env("RP_NAME", "Minimal WebAuthn"),
	}

	s, err := app.NewServer(cfg)
	if err != nil {
		log.Fatalf("server init: %v", err)
	}

	log.Printf("listening on %s", cfg.ListenAddr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func env(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		panic("missing env var: " + k)
	}
	return v
}
