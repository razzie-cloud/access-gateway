package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPostgresConcurrentBootstrapInitialization(t *testing.T) {
	s := postgresServer(t)
	_, err := s.db.ExecContext(t.Context(), `DELETE FROM app_states WHERE key='bootstrap_token_sha256'`)
	require.NoError(t, err)
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	const replicas = 8
	start := make(chan struct{})
	results := make(chan error, replicas)
	for range replicas {
		db, err := sql.Open("pgx", s.cfg.DatabaseURL)
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		peer := &Server{db: db}
		go func() {
			<-start
			results <- peer.ensureBootstrapTokenIfNoUsers(t.Context())
		}()
	}
	close(start)
	for range replicas {
		require.NoError(t, <-results)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	require.Len(t, lines, 1, "only the winning replica may log a token")
	var event struct {
		Event string `json:"event"`
		Token string `json:"bootstrap_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &event))
	require.Equal(t, "bootstrap.token_created", event.Event)
	require.Len(t, event.Token, 64)
	hash, err := s.getAppState(t.Context(), "bootstrap_token_sha256")
	require.NoError(t, err)
	require.Equal(t, hashToken(event.Token), hash)

	output.Reset()
	require.NoError(t, s.ensureBootstrapTokenIfNoUsers(t.Context()))
	require.Empty(t, output.String(), "restart must preserve the token without logging a new one")
	hashAfter, err := s.getAppState(t.Context(), "bootstrap_token_sha256")
	require.NoError(t, err)
	require.Equal(t, hash, hashAfter)
}

func TestPostgresBootstrapInitializationWaitsForEnrollment(t *testing.T) {
	s := postgresServer(t)
	tx, err := s.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer tx.Rollback()
	require.NoError(t, lockBootstrap(t.Context(), tx))
	// Model an enrollment that has consumed the token but has not committed yet.
	id := uuid.New()
	_, err = tx.ExecContext(t.Context(), `INSERT INTO users(id,username,is_admin,created_at) VALUES($1,'admin',TRUE,0)`, id[:])
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(), `DELETE FROM app_states WHERE key='bootstrap_token_sha256'`)
	require.NoError(t, err)

	uri, err := url.Parse(s.cfg.DatabaseURL)
	require.NoError(t, err)
	query := uri.Query()
	name := "bootstrap_waiter_" + uuid.NewString()
	query.Set("application_name", name)
	uri.RawQuery = query.Encode()
	db, err := sql.Open("pgx", uri.String())
	require.NoError(t, err)
	defer db.Close()
	peer := &Server{db: db}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- peer.ensureBootstrapTokenIfNoUsers(ctx) }()
	require.Eventually(t, func() bool {
		var waiting bool
		err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event='advisory')`, name).Scan(&waiting)
		return err == nil && waiting
	}, 5*time.Second, 10*time.Millisecond, "startup must wait on the enrollment lock before checking users")
	require.NoError(t, tx.Commit())
	require.NoError(t, <-result)
	var tokens int
	require.NoError(t, s.db.QueryRowContext(t.Context(), `SELECT count(*) FROM app_states WHERE key='bootstrap_token_sha256'`).Scan(&tokens))
	require.Zero(t, tokens, "startup recreated a consumed bootstrap token")
}
