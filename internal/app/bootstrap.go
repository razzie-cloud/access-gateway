package app

import (
	"context"
	"database/sql"
	"time"

	"github.com/razzie-cloud/access-gateway/internal/logging"
)

// Shared by token creation and enrollment, including when the token row is absent.
const bootstrapLockID int64 = 0x72617a626f6f7473

func lockBootstrap(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, bootstrapLockID)
	return err
}

func (s *Server) ensureBootstrapTokenIfNoUsers(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockBootstrap(ctx, tx); err != nil {
		return err
	}
	var hasUsers bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&hasUsers); err != nil {
		return err
	}
	if hasUsers {
		return nil
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO app_states(key,value,updated_at)
 VALUES('bootstrap_token_sha256',$1,$2) ON CONFLICT (key) DO NOTHING`, hashToken(token), time.Now().Unix())
	if err != nil {
		return err
	}
	created, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// Never log an uncommitted token or a losing replica's unused token.
	if created == 1 {
		logging.BootstrapToken(ctx, token)
	}
	return nil
}
