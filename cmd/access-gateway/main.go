package main

import (
	"fmt"
	"log"

	"github.com/razzie-cloud/access-gateway/internal/app"
	"github.com/razzie-cloud/access-gateway/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	addr := fmt.Sprintf(":%d", cfg.ServicePort)
	s, err := app.NewServer(app.Config{
		ListenAddr:  addr,
		DatabaseURL: cfg.PostgresURI,
		Origin:      cfg.Origin,
		RPID:        cfg.RPID,
		RPName:      cfg.RPName,
	})
	if err != nil {
		log.Fatalf("server init: %v", err)
	}

	log.Printf("listening on %s", addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
