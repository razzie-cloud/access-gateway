package app

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var errDeviceInUse = errors.New("device is in use")

type deviceView struct {
	ID        int64
	Username  string
	Name      string
	CreatedAt time.Time
	Current   bool
	InUse     bool
}

type sessionView struct {
	sessionSummary
	DeviceName string
	Current    bool
}

func validDeviceName(name string) bool {
	return strings.TrimSpace(name) != "" && utf8.ValidString(name) && utf8.RuneCountInString(name) <= 80 && !strings.ContainsFunc(name, unicode.IsControl)
}

func validSessionID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 32 && id == strings.ToLower(id)
}

func (s *Server) listDevices(ctx context.Context, actor User) ([]deviceView, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT c.id,u.username,c.device_name,c.created_at
 FROM webauthn_credentials c JOIN users u ON u.id=c.user_id
 WHERE c.user_id=$1 OR $2 ORDER BY u.username,c.created_at,c.id`, actor.ID, actor.IsAdmin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []deviceView
	for rows.Next() {
		var d deviceView
		var created int64
		if err := rows.Scan(&d.ID, &d.Username, &d.Name, &created); err != nil {
			return nil, err
		}
		d.CreatedAt = time.Unix(created, 0)
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

func (s *Server) renameDevice(ctx context.Context, actor User, id int64, name string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE webauthn_credentials SET device_name=$1 WHERE id=$2 AND (user_id=$3 OR $4)`, name, id, actor.ID, actor.IsAdmin)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}

func (s *Server) removeDevice(ctx context.Context, actor User, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var username string
	err = tx.QueryRowContext(ctx, `SELECT u.username FROM webauthn_credentials c JOIN users u ON u.id=c.user_id
 WHERE c.id=$1 AND (c.user_id=$2 OR $3) FOR UPDATE OF c`, id, actor.ID, actor.IsAdmin).Scan(&username)
	if err != nil {
		return err
	}
	// Check Redis after acquiring the same device lock used by login completion.
	sessions, err := s.sessions.ListSessions(ctx)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		// Legacy sessions cannot identify their device. Conservatively protect
		// the account's devices until those sessions are ended or expire.
		if session.Username == username && (session.DeviceID == id || session.DeviceID == 0) {
			return errDeviceInUse
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}
