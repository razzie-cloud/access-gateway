package app

import (
	"database/sql"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresUsernamePolicy(t *testing.T) {
	s := postgresServer(t)
	addUser(t, s, "Admin", true)
	member := addUser(t, s, "Alice_9.-", false)
	for _, name := range []string{"Alice_9.-", "alice_9.-", "ALICE_9.-"} {
		u, err := s.getUserByUsername(t.Context(), name)
		require.NoError(t, err)
		assert.Equal(t, member.ID, u.ID)
		assert.Equal(t, member.Username, u.Username, "lookup must preserve stored spelling")
	}
	// Even unvalidated lookup callers must not fold Unicode into an ASCII name.
	addUser(t, s, "Kate", false)
	_, err := s.getUserByUsername(t.Context(), "Kate")
	assert.ErrorIs(t, err, sql.ErrNoRows)
	for _, name := range []string{"", "alice bob", "álîce", "alice@home", "alice\nbob", "alice["} {
		id := uuid.New()
		_, err := s.db.Exec(`INSERT INTO users(id,username,is_admin,created_at) VALUES($1,$2,FALSE,0)`, id[:], name)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr, "database accepted %q", name)
		assert.Equal(t, "23514", pgErr.Code)
		assert.Equal(t, "users_username_format_check", pgErr.ConstraintName)
		w := request(s, "POST", "/ui/users", url.Values{"username": {name}}.Encode(), "Admin-session")
		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	}
	for _, name := range []string{"Alice_9.-", "ALICE_9.-"} {
		id := uuid.New()
		_, err := s.db.Exec(`INSERT INTO users(id,username,is_admin,created_at) VALUES($1,$2,FALSE,0)`, id[:], name)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "23505", pgErr.Code)
		assert.Equal(t, "users_username_ci_key", pgErr.ConstraintName)
		w := request(s, "POST", "/ui/users", url.Values{"username": {name}}.Encode(), "Admin-session")
		assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	}
	w := request(s, "POST", "/ui/users", "username=+New.User_2-+", "Admin-session")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	u, err := s.getUserByUsername(t.Context(), "new.user_2-")
	require.NoError(t, err)
	assert.Equal(t, "New.User_2-", u.Username)
	// A member can target their own account with any capitalization, but never
	// the administrator. The resulting link remains bound to the original UUID.
	token := issueLink(t, s, member.Username, "aLiCe_9.-", 60)
	link, err := s.registrationFromLink(t.Context(), token)
	require.NoError(t, err)
	assert.Equal(t, member.ID, link.User.ID)
	assert.Equal(t, member.Username, link.User.Username)
	w = request(s, "POST", "/ui/links", "username=ADMIN&minutes=60", member.Username+"-session")
	assert.Equal(t, http.StatusForbidden, w.Code)
}
