package db

import (
	"context"
	"database/sql"
	"embed"
	"io/fs"
	"log/slog"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"github.com/razzie-cloud/access-gateway/internal/logging"
)

//go:embed migrations/*.sql
var migrations embed.FS

func RunMigrations(db *sql.DB) error {
	root, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, root, goose.WithSessionLocker(locker), goose.WithLogger(goose.NopLogger()))
	if err != nil {
		return err
	}
	start := time.Now()
	results, err := provider.Up(context.Background())
	if err != nil {
		return logging.Wrap("migrate_postgres", err)
	}
	if len(results) > 0 {
		slog.Info("Database migrations applied", "event", "migrations.applied", "component", "postgres", "count", len(results), "version", results[len(results)-1].Source.Version, "duration_ms", time.Since(start).Milliseconds())
	}
	return nil
}
