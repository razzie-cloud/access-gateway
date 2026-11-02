package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresLoginBeginFiltersAndPadsAccounts(t *testing.T) {
	s := postgresServer(t)
	alice := addUser(t, s, "alice", false)
	bob := addUser(t, s, "bob", false)
	addUser(t, s, "unenrolled", false)
	_, aliceKey := addDevice(t, s, alice, "Phone")
	_, bobKey := addDevice(t, s, bob, "Short")
	addDevice(t, s, bob, "Other")
	addDevice(t, s, bob, "Much longer credential ID")
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	var reference map[string]any
	lists := map[string][]protocol.CredentialDescriptor{}
	seen := make(map[string]bool)
	for _, name := range []string{"alice", "bob", "unknown", "unenrolled", "unknown", "another-unknown"} {
		body := `{"username":" ` + name + ` "}`
		w := request(s, "POST", "/api/login/begin", body, "")
		require.Equal(t, 200, w.Code, w.Body.String())
		var options map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &options))
		var assertion protocol.CredentialAssertion
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &assertion))
		allowed := assertion.Response.AllowedCredentials
		require.NotEmpty(t, allowed)
		if before, ok := lists[name]; ok {
			assert.Equal(t, before, allowed, "repeated queries must keep IDs stable")
		}
		lists[name] = allowed
		var lengths []int
		var ids [][]byte
		for _, credential := range allowed {
			assert.Empty(t, credential.Transport)
			assert.Equal(t, protocol.PublicKeyCredentialType, credential.Type)
			lengths = append(lengths, len(credential.CredentialID))
			ids = append(ids, credential.CredentialID)
		}
		if name == "alice" {
			assert.Contains(t, ids, aliceKey.ID)
			assert.NotContains(t, ids, bobKey.ID)
		} else {
			assert.NotContains(t, ids, aliceKey.ID)
		}
		if name != "bob" {
			assert.NotContains(t, ids, bobKey.ID)
		}
		publicKey := options["publicKey"].(map[string]any)
		challenge := publicKey["challenge"].(string)
		assert.False(t, seen[challenge])
		seen[challenge] = true
		// Only the opaque credential values and fresh challenge may differ.
		publicKey["allowCredentials"] = lengths
		delete(publicKey, "challenge")
		if reference == nil {
			reference = options
		} else {
			assert.Equal(t, reference, options)
		}
		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		claimed, sd, ok, err := s.sessions.GetLogin(t.Context(), cookies[0].Value)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, name, claimed)
		assert.Len(t, sd.UserID, 16)
		assert.NotEmpty(t, sd.AllowedCredentialIDs)
		if name == "alice" {
			assert.Equal(t, alice.ID, sd.UserID)
			assert.Equal(t, [][]byte{aliceKey.ID}, sd.AllowedCredentialIDs)
		}
		assert.Contains(t, output.String(), `"claimed_username":"`+name+`"`)
		assert.NotContains(t, output.String(), challenge)
		assert.NotContains(t, output.String(), cookies[0].Value)
	}
	assert.NotEqual(t, lists["unknown"], lists["another-unknown"])
}

func TestPostgresLoginDecoysSurviveReplicaAndRestart(t *testing.T) {
	s := postgresServer(t)
	before, _, err := s.loginCredentials(t.Context(), "unknown")
	require.NoError(t, err)
	require.NotEmpty(t, before, "empty database must still return a filter")
	peer := &Server{db: s.db, cfg: s.cfg}
	require.NoError(t, peer.ensureLoginSecret(t.Context()))
	assert.Equal(t, s.loginSecret, peer.loginSecret)
	after, _, err := peer.loginCredentials(t.Context(), "unknown")
	require.NoError(t, err)
	assert.Equal(t, before, after)
	peer.cfg.Origin = "https://another.example"
	other, _, err := peer.loginCredentials(t.Context(), "unknown")
	require.NoError(t, err)
	assert.NotEqual(t, before, other)
}

func signingDevice(t *testing.T, s *Server, user User) (*webauthn.Credential, *ecdsa.PrivateKey, int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicKey, err := cbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1,
		-2: key.X.FillBytes(make([]byte, 32)),
		-3: key.Y.FillBytes(make([]byte, 32)),
	})
	require.NoError(t, err)
	id, credential := addDevice(t, s, user, "Signing device")
	credential.PublicKey = publicKey
	data, err := marshalCredential(credential)
	require.NoError(t, err)
	_, err = s.db.Exec(`UPDATE webauthn_credentials SET credential_json=$1 WHERE id=$2`, data, id)
	require.NoError(t, err)
	return credential, key, id
}

func signedAssertion(t *testing.T, s *Server, key *ecdsa.PrivateKey, rawID, handle []byte, challenge, origin string) string {
	t.Helper()
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	require.NoError(t, err)
	rpHash := sha256.Sum256([]byte(s.cfg.RPID))
	authData := make([]byte, 37)
	copy(authData, rpHash[:])
	authData[32] = 0x05 // User present and user verified.
	binary.BigEndian.PutUint32(authData[33:], 1)
	clientHash := sha256.Sum256(client)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)
	encode := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id": encode(rawID), "rawId": encode(rawID), "type": "public-key",
		"response":               map[string]any{"clientDataJSON": encode(client), "authenticatorData": encode(authData), "signature": encode(signature), "userHandle": encode(handle)},
		"clientExtensionResults": map[string]any{},
	})
	require.NoError(t, err)
	return string(body)
}

func loginFinishRequest(s *Server, sid, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/login/finish", strings.NewReader(body))
	r.Header.Set("Origin", s.cfg.Origin)
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

func TestPostgresNamedLoginSignatureBindingAndReplay(t *testing.T) {
	s := postgresServer(t)
	alice := addUser(t, s, "alice", false)
	bob := addUser(t, s, "bob", false)
	credential, key, _ := signingDevice(t, s, alice)
	w := request(s, "POST", "/api/login/begin", `{"username":"alice"}`, "")
	require.Equal(t, 200, w.Code)
	sid := w.Result().Cookies()[0].Value
	_, sd, ok, err := s.sessions.GetLogin(t.Context(), sid)
	require.NoError(t, err)
	require.True(t, ok)
	for _, tc := range []struct {
		name              string
		handle            []byte
		challenge, origin string
	}{
		{"wrong account", bob.ID, sd.Challenge, s.cfg.Origin},
		{"unknown account", make([]byte, 16), sd.Challenge, s.cfg.Origin},
		{"wrong challenge", alice.ID, "another-challenge-with-enough-entropy", s.cfg.Origin},
		{"wrong origin", alice.ID, sd.Challenge, "https://evil.example"},
	} {
		body := signedAssertion(t, s, key, credential.ID, tc.handle, tc.challenge, tc.origin)
		w = loginFinishRequest(s, sid, body)
		require.Equal(t, 401, w.Code, tc.name+": "+w.Body.String())
		assert.JSONEq(t, `{"error":"`+loginFailureMessage+`"}`, w.Body.String())
		assert.Empty(t, w.Result().Cookies())
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	w = loginFinishRequest(s, sid, signedAssertion(t, s, wrongKey, credential.ID, alice.ID, sd.Challenge, s.cfg.Origin))
	require.Equal(t, 401, w.Code, "invalid signature must not authenticate")
	assert.Empty(t, w.Result().Cookies())
	body := signedAssertion(t, s, key, credential.ID, alice.ID, sd.Challenge, s.cfg.Origin)
	w = loginFinishRequest(s, sid, body)
	require.Equal(t, 200, w.Code, w.Body.String())
	var auth *http.Cookie
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == "auth" {
			auth = cookie
		}
	}
	require.NotNil(t, auth)
	name, ok, err := s.sessions.GetAuth(t.Context(), auth.Value)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, alice.Username, name)
	w = loginFinishRequest(s, sid, body)
	assert.Equal(t, 401, w.Code)
	assert.Empty(t, w.Result().Cookies())
}

func TestPostgresNamedLoginAccountBindingAndOptionalHandle(t *testing.T) {
	s := postgresServer(t)
	alice := addUser(t, s, "alice", false)
	bob := addUser(t, s, "bob", false)
	credential, key, _ := signingDevice(t, s, alice)
	signingDevice(t, s, bob)
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, tc := range []struct {
		username string
		handle   []byte
		status   int
	}{
		{"bob", alice.ID, 401},
		{"bob", nil, 401},
		{"unknown", alice.ID, 401},
		{"alice", nil, 200},
	} {
		s.limits = newRequestLimits()
		w := request(s, "POST", "/api/login/begin", `{"username":"`+tc.username+`"}`, "")
		require.Equal(t, 200, w.Code, w.Body.String())
		sid := w.Result().Cookies()[0].Value
		_, sd, ok, err := s.sessions.GetLogin(t.Context(), sid)
		require.NoError(t, err)
		require.True(t, ok)
		body := signedAssertion(t, s, key, credential.ID, tc.handle, sd.Challenge, s.cfg.Origin)
		w = loginFinishRequest(s, sid, body)
		require.Equal(t, tc.status, w.Code, w.Body.String())
		if tc.status == 401 {
			assert.JSONEq(t, `{"error":"`+loginFailureMessage+`"}`, w.Body.String())
			assert.Empty(t, w.Result().Cookies())
			assert.Contains(t, output.String(), `"claimed_username":"`+tc.username+`"`)
		}
		assert.NotContains(t, output.String(), body)
		assert.NotContains(t, output.String(), sid)
	}
}

func TestPostgresDummyLoginCannotBecomeValidAfterEnrollment(t *testing.T) {
	s := postgresServer(t)
	w := request(s, "POST", "/api/login/begin", `{"username":"alice"}`, "")
	require.Equal(t, 200, w.Code, w.Body.String())
	sid := w.Result().Cookies()[0].Value
	_, sd, _, err := s.sessions.GetLogin(t.Context(), sid)
	require.NoError(t, err)
	alice := addUser(t, s, "alice", false)
	credential, key, _ := signingDevice(t, s, alice)
	body := signedAssertion(t, s, key, credential.ID, nil, sd.Challenge, s.cfg.Origin)
	w = loginFinishRequest(s, sid, body)
	assert.Equal(t, 401, w.Code, w.Body.String())
	assert.Empty(t, w.Result().Cookies())
}

func TestLoginFailureLogsClaimedUsername(t *testing.T) {
	s := unitServer()
	var err error
	s.wa, err = webauthn.New(&webauthn.Config{RPID: "auth.example", RPOrigins: []string{s.cfg.Origin}})
	require.NoError(t, err)
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	// Anonymous ceremonies from the old flow must restart. Even that failure
	// must log a stored claimed name without allowing newline injection.
	claimed := "alice\nforged log entry"
	testMemory(s).PutLogin("old", claimed, webauthn.SessionData{})
	w := loginFinishRequest(s, "old", "secret assertion body")
	assert.Equal(t, 401, w.Code)
	assert.Contains(t, output.String(), `"claimed_username":"alice\nforged log entry"`)
	assert.NotContains(t, output.String(), "alice\nforged")
	assert.NotContains(t, output.String(), "secret assertion body")
}

func TestPostgresDiscoverableReenrollmentOptions(t *testing.T) {
	s := postgresServer(t)
	u := addUser(t, s, "alice", false)
	addDevice(t, s, u, "Legacy key")
	id, discoverable := addDevice(t, s, u, "Discoverable key")
	rk := true
	discoverable.Extensions.RK = &rk
	data, err := marshalCredential(discoverable)
	require.NoError(t, err)
	_, err = s.db.Exec(`UPDATE webauthn_credentials SET credential_json=$1 WHERE id=$2`, data, id)
	require.NoError(t, err)
	token := issueLink(t, s, u.Username, "", 60)
	w := request(s, "POST", "/api/register/begin", `{"linkToken":"`+token+`"}`, "")
	require.Equal(t, 200, w.Code)
	var options protocol.CredentialCreation
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &options))
	assert.Equal(t, protocol.ResidentKeyRequirementRequired, options.Response.AuthenticatorSelection.ResidentKey)
	require.NotNil(t, options.Response.AuthenticatorSelection.RequireResidentKey)
	assert.True(t, *options.Response.AuthenticatorSelection.RequireResidentKey)
	require.Len(t, options.Response.CredentialExcludeList, 1)
	assert.Equal(t, discoverable.ID, []byte(options.Response.CredentialExcludeList[0].CredentialID))
}

func TestLegacyRegistrationCeremonyMustRestart(t *testing.T) {
	s := unitServer()
	testMemory(s).PutRegistration("legacy", registrationContext{}, webauthn.SessionData{})
	r := httptest.NewRequest("POST", "/api/register/finish", strings.NewReader(`{}`))
	r.Header.Set("Origin", s.cfg.Origin)
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "sid", Value: "legacy"})
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "start registration again")
}
