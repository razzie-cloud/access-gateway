package app

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPostgresLogsExcludeSQLAndRegistrationCapabilities(t *testing.T) {
	s := postgresServer(t)
	addUser(t, s, "member", false)
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	w := request(s, "GET", "/api/bootstrap", "", "")
	require.Equal(t, 200, w.Code)
	require.Empty(t, output.String(), "routine go-rel reads must be silent")
	token := issueLink(t, s, "member", "member", 10)
	require.NotContains(t, output.String(), token)
	require.NotContains(t, output.String(), "member-session")
	require.NotContains(t, output.String(), "SELECT")
	require.NotContains(t, output.String(), "INSERT")
	require.NotContains(t, output.String(), "registration_links")
	var event map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event))
	require.Equal(t, "registration_link.issued", event["event"])
	require.NotEmpty(t, event["actor_user_id"])
	require.NotEmpty(t, event["request_id"])
}

func TestLoginClaimIsBoundedAndEscapedInJSON(t *testing.T) {
	s := unitServer()
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	r := httptest.NewRequest("POST", "/api/login/finish", nil)
	s.rejectLogin(httptest.NewRecorder(), r, strings.Repeat("a", 100)+"\nforged", "invalid assertion or unknown credential")
	var event map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event))
	require.Len(t, event["claimed_username"], 64)
	require.Equal(t, "login.rejected", event["event"])
}
