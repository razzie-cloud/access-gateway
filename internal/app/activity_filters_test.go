package app

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActivityUserFilter(t *testing.T) {
	id, other := uuid.New(), uuid.New()
	actor := User{ID: id[:], Username: "Admin", IsAdmin: true}
	users := []adminUser{{User: actor, UUID: id.String()}, {User: User{Username: "all"}, UUID: other.String()}}
	for _, tc := range []struct{ value, label, username string }{
		{"", "Admin (you)", "Admin"}, {id.String(), "Admin (you)", "Admin"},
		{other.String(), "all", "all"}, {"all", "All users", ""},
	} {
		f, err := newActivityUserFilter("devices", tc.value, actor, users)
		require.NoError(t, err)
		assert.Equal(t, tc.label, f.Label)
		assert.True(t, f.includes(tc.username))
		assert.Equal(t, tc.value == "all", f.includes("someone-else"))
		require.Len(t, f.Options, 3)
	}
	for _, value := range []string{"Admin", "ALL", "not-a-uuid", uuid.NewString(), "<script>"} {
		_, err := newActivityUserFilter("devices", value, actor, users)
		assert.ErrorIs(t, err, errActivityUserFilter)
	}
}

func TestFrontendActivityUserFilters(t *testing.T) {
	id := uuid.New()
	actor := User{ID: id[:], Username: "Admin", IsAdmin: true}
	users := []adminUser{{User: actor, UUID: id.String()}, {User: User{Username: "<escaped>"}, UUID: uuid.NewString()}}
	devices, err := newActivityUserFilter("devices", "", actor, users)
	require.NoError(t, err)
	sessions, err := newActivityUserFilter("sessions", "all", actor, users)
	require.NoError(t, err)
	data := viewData{User: &actor, DevicesFilter: devices, SessionsFilter: sessions}
	var html bytes.Buffer
	require.NoError(t, templates.ExecuteTemplate(&html, "activity", data))
	for _, panel := range []string{"devices", "sessions"} {
		assert.Contains(t, html.String(), `id="`+panel+`-user-filter"`)
		assert.Contains(t, html.String(), `name="`+panel+`_user"`)
	}
	assert.Contains(t, html.String(), `href="/?devices_user=`+id.String()+`"`)
	assert.Contains(t, html.String(), `hx-include="#sessions-user-value"`)
	assert.Contains(t, html.String(), `hx-include="#devices-user-value"`)
	assert.Contains(t, html.String(), `&lt;escaped&gt;`)
	assert.NotContains(t, html.String(), `<escaped>`)
	actor.IsAdmin = false
	data.DevicesFilter, data.SessionsFilter = nil, nil
	html.Reset()
	require.NoError(t, templates.ExecuteTemplate(&html, "activity", data))
	assert.NotContains(t, html.String(), `user-filter`)
	assert.NotContains(t, html.String(), `_user"`)
}

func TestPostgresActivityUserFilters(t *testing.T) {
	s := postgresServer(t)
	admin := addUser(t, s, "admin", true)
	alice := addUser(t, s, "Alice", false)
	addUser(t, s, "empty", false)
	require.NoError(t, s.sessions.DeleteAuth(t.Context(), "empty-session"))
	adminDevice, _ := addDevice(t, s, admin, "Admin laptop")
	aliceDevice, _ := addDevice(t, s, alice, "Alice phone")
	spare, _ := addDevice(t, s, alice, "Alice spare")
	bindDeviceSession(t, s, "admin-session", admin, adminDevice)
	bindDeviceSession(t, s, "Alice-session", alice, aliceDevice)
	mintRedisAppSession(t, s.sessions.(*redisSessions), "Alice-session")
	aliceID, _ := uuid.FromBytes(alice.ID)
	for _, tc := range []struct {
		query, token              string
		devices, sessions         int
		deviceOwner, sessionOwner string
	}{
		{"", "admin-session", 1, 1, "admin", "admin"},
		{"devices_user=all&sessions_user=all", "admin-session", 3, 2, "", ""},
		{"devices_user=" + aliceID.String(), "admin-session", 2, 1, "Alice", "admin"},
		{"sessions_user=" + aliceID.String(), "admin-session", 1, 1, "admin", "Alice"},
		{"devices_user=all&sessions_user=all", "Alice-session", 2, 1, "Alice", "Alice"},
		{"devices_user=invalid&sessions_user=invalid", "Alice-session", 2, 1, "Alice", "Alice"},
	} {
		t.Run(tc.query+tc.token, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/ui/activity?"+tc.query, nil)
			r.AddCookie(&http.Cookie{Name: "auth", Value: tc.token})
			actor, err := s.currentUser(r)
			require.NoError(t, err)
			data, err := s.activity(r, actor)
			require.NoError(t, err)
			require.Len(t, data.Devices, tc.devices)
			require.Len(t, data.Sessions, tc.sessions)
			for _, d := range data.Devices {
				if tc.deviceOwner != "" {
					assert.Equal(t, tc.deviceOwner, d.Username)
				}
			}
			for _, session := range data.Sessions {
				if tc.sessionOwner != "" {
					assert.Equal(t, tc.sessionOwner, session.Username)
				}
			}
			if tc.deviceOwner == "Alice" {
				assert.True(t, data.Devices[0].InUse, "filtering sessions must not unprotect devices")
			}
			if tc.sessionOwner == "Alice" {
				require.Len(t, data.Sessions[0].Apps, 1)
				assert.Equal(t, "Alice phone", data.Sessions[0].DeviceName)
			}
		})
	}
	// Unenrolled accounts remain selectable and produce empty panels.
	empty, err := s.getUserByUsername(t.Context(), "empty")
	require.NoError(t, err)
	emptyID, _ := uuid.FromBytes(empty.ID)
	w := request(s, "GET", "/ui/activity?devices_user="+emptyID.String()+"&sessions_user="+emptyID.String(), "", "admin-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "No devices found.")
	assert.Contains(t, w.Body.String(), "No active sessions.")
	// Invalid scopes keep the old panel and its selected account on the browser.
	for _, value := range []string{"bad", uuid.NewString()} {
		r := httptest.NewRequest("GET", "/ui/activity?devices_user="+value, nil)
		r.AddCookie(&http.Cookie{Name: "auth", Value: "admin-session"})
		r.Header.Set("HX-Request", "true")
		r.Header.Set("HX-Target", "devices")
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		assert.Equal(t, 400, w.Code)
		assert.Equal(t, "#devices-feedback", w.Header().Get("HX-Retarget"))
		assert.NotContains(t, w.Body.String(), `id="devices"`)
	}
	// Both scopes survive mutations and remain independent of action authority.
	form := url.Values{"device_id": {fmt.Sprint(spare)}, "device_name": {"Renamed spare"}, "devices_user": {aliceID.String()}, "sessions_user": {"all"}}
	w = request(s, "POST", "/ui/devices/rename", form.Encode(), "admin-session")
	require.Equal(t, 200, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "Renamed spare")
	assert.Contains(t, w.Body.String(), `name="devices_user" value="`+aliceID.String()+`"`)
	assert.Contains(t, w.Body.String(), `name="sessions_user" value="all"`)
	form.Set("device_id", fmt.Sprint(adminDevice))
	assert.Equal(t, 404, request(s, "POST", "/ui/devices/rename", form.Encode(), "Alice-session").Code)
	// Ordinary navigation forwards only the chosen activity parameters to HTMX.
	w = request(s, "GET", "/?devices_user="+aliceID.String()+"&sessions_user=all&unrelated=ignored", "", "admin-session")
	require.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), `hx-get="/ui/activity?devices_user=`+aliceID.String()+`&amp;sessions_user=all"`)
	assert.NotContains(t, w.Body.String(), "unrelated")
	// Demotion is checked afresh; old admin scope values never grant visibility.
	_, err = s.db.Exec(`UPDATE users SET is_admin=FALSE WHERE username='admin'`)
	require.NoError(t, err)
	w = request(s, "GET", "/ui/activity?devices_user=all&sessions_user=all", "", "admin-session")
	require.Equal(t, 200, w.Code)
	assert.NotContains(t, w.Body.String(), "Alice phone")
	assert.NotContains(t, w.Body.String(), "user-filter")
}
