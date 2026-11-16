package db

import (
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsernameMigration(t *testing.T) {
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL unset; PostgreSQL integration test")
	}
	admin, err := sql.Open("pgx", raw)
	require.NoError(t, err)
	defer admin.Close()
	for _, tc := range []struct {
		name      string
		usernames []string
		valid     bool
	}{
		{"valid", []string{"Alice_9.-", "BOB", strings.Repeat("A", 64)}, true},
		{"case collision", []string{"Alice", "alice"}, false},
		{"unicode", []string{"álîce"}, false},
		{"empty", []string{""}, false},
		{"trailing newline", []string{"alice\n"}, false},
		{"punctuation", []string{"alice@home"}, false},
		{"overlong", []string{strings.Repeat("a", 65)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			schema := "username_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			_, err := admin.ExecContext(t.Context(), "CREATE SCHEMA "+schema)
			require.NoError(t, err)
			t.Cleanup(func() { _, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE") })
			uri, err := url.Parse(raw)
			require.NoError(t, err)
			query := uri.Query()
			query.Set("search_path", schema)
			uri.RawQuery = query.Encode()
			db, err := sql.Open("pgx", uri.String())
			require.NoError(t, err)
			defer db.Close()
			provider, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS("migrations"), goose.WithLogger(goose.NopLogger()))
			require.NoError(t, err)
			_, err = provider.UpTo(t.Context(), 4)
			require.NoError(t, err)
			for _, name := range tc.usernames {
				id := uuid.New()
				_, err := db.ExecContext(t.Context(), `INSERT INTO users(id,username,created_at) VALUES($1,$2,0)`, id[:], name)
				require.NoError(t, err)
			}
			err = RunMigrations(db)
			if tc.valid {
				require.NoError(t, err)
				id := uuid.New()
				_, err = db.ExecContext(t.Context(), `INSERT INTO users(id,username,created_at) VALUES($1,'aLiCe_9.-',0)`, id[:])
				require.Error(t, err, "upgraded database must reject case-only duplicates")
				// Downgrading restores the old exact uniqueness constraint.
				_, err = provider.DownTo(t.Context(), 4)
				require.NoError(t, err)
				_, err = db.ExecContext(t.Context(), `INSERT INTO users(id,username,created_at) VALUES($1,'aLiCe_9.-',0)`, id[:])
				require.NoError(t, err)
				_, err = db.ExecContext(t.Context(), `DELETE FROM users WHERE id=$1`, id[:])
				require.NoError(t, err)
				require.NoError(t, RunMigrations(db))
			} else {
				require.Error(t, err, "migration must reject incompatible existing users")
				var version int64
				require.NoError(t, db.QueryRowContext(t.Context(), `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&version))
				assert.EqualValues(t, 4, version, "failed migration must remain unapplied")
				var constraints int
				require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM pg_constraint WHERE conrelid='users'::regclass AND conname='users_username_key'`).Scan(&constraints))
				assert.Equal(t, 1, constraints, "failed migration must preserve original uniqueness")
				var checkExists bool
				require.NoError(t, db.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='users'::regclass AND conname='users_username_format_check')`).Scan(&checkExists))
				assert.False(t, checkExists, "migration must roll back every schema change")
			}
			rows, err := db.QueryContext(t.Context(), `SELECT username FROM users`)
			require.NoError(t, err)
			defer rows.Close()
			var names []string
			for rows.Next() {
				var name string
				require.NoError(t, rows.Scan(&name))
				names = append(names, name)
			}
			require.NoError(t, rows.Err())
			assert.ElementsMatch(t, tc.usernames, names, "migration must never rename or merge users")
		})
	}
}
