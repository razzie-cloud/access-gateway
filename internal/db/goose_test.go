package db

import (
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func TestConcurrentMigrations(t *testing.T) {
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL unset; PostgreSQL integration test")
	}
	admin, err := sql.Open("pgx", raw)
	require.NoError(t, err)
	defer admin.Close()
	for _, initial := range []int64{0, 1} {
		t.Run(string(rune('0'+initial)), func(t *testing.T) {
			schema := "migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			_, err := admin.ExecContext(t.Context(), "CREATE SCHEMA "+schema)
			require.NoError(t, err)
			t.Cleanup(func() { _, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE") })
			uri, err := url.Parse(raw)
			require.NoError(t, err)
			query := uri.Query()
			query.Set("search_path", schema)
			uri.RawQuery = query.Encode()
			if initial != 0 {
				db, err := sql.Open("pgx", uri.String())
				require.NoError(t, err)
				provider, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS("migrations"), goose.WithLogger(goose.NopLogger()))
				require.NoError(t, err)
				_, err = provider.UpTo(t.Context(), initial)
				require.NoError(t, err)
				require.NoError(t, db.Close())
			}
			// Separate pools/providers model replicas, including version-table creation.
			const replicas = 8
			start := make(chan struct{})
			results := make(chan error, replicas)
			for range replicas {
				db, err := sql.Open("pgx", uri.String())
				require.NoError(t, err)
				db.SetMaxOpenConns(2)
				t.Cleanup(func() { _ = db.Close() })
				go func() {
					<-start
					results <- RunMigrations(db)
				}()
			}
			close(start)
			for range replicas {
				require.NoError(t, <-results)
			}
			var applied int
			err = admin.QueryRowContext(t.Context(), "SELECT count(*) FROM "+schema+".goose_db_version WHERE is_applied AND version_id > 0").Scan(&applied)
			require.NoError(t, err)
			require.Equal(t, 3, applied)
		})
	}
}
