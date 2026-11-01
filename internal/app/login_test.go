package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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

func TestLoginBeginHasNoAccountSpecificResponse(t *testing.T) {
	// There is deliberately no database on this server: initiation must not
	// inspect account existence, credential count, IDs, or transports.
	s := unitServer()
	var err error
	s.wa, err = webauthn.New(&webauthn.Config{RPID: "auth.example", RPOrigins: []string{s.cfg.Origin}})
	require.NoError(t, err)
	var reference map[string]any
	seen := make(map[string]bool)
	for _, body := range []string{`{}`, `{"username":""}`, `{"username":"alice"}`, `{"username":"unknown"}`} {
		w := request(s, "POST", "/api/login/begin", body, "")
		require.Equal(t, 200, w.Code)
		var options map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &options))
		publicKey := options["publicKey"].(map[string]any)
		challenge := publicKey["challenge"].(string)
		assert.False(t, seen[challenge])
		seen[challenge] = true
		assert.NotContains(t, publicKey, "allowCredentials")
		delete(publicKey, "challenge")
		if reference == nil {
			reference = options
		} else {
			assert.Equal(t, reference, options)
		}
		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		name, sd, ok, err := s.sessions.GetLogin(t.Context(), cookies[0].Value)
		require.NoError(t, err)
		require.True(t, ok)
		assert.Empty(t, name)
		assert.Empty(t, sd.UserID)
		assert.Empty(t, sd.AllowedCredentialIDs)
	}
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

func TestPostgresDiscoverableLoginSignatureBindingAndReplay(t *testing.T) {
	s := postgresServer(t)
	alice := addUser(t, s, "alice", false)
	bob := addUser(t, s, "bob", false)
	credential, key, _ := signingDevice(t, s, alice)
	w := request(s, "POST", "/api/login/begin", `{}`, "")
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
		{"missing user handle", nil, sd.Challenge, s.cfg.Origin},
		{"wrong challenge", alice.ID, "another-challenge-with-enough-entropy", s.cfg.Origin},
		{"wrong origin", alice.ID, sd.Challenge, "https://evil.example"},
	} {
		body := signedAssertion(t, s, key, credential.ID, tc.handle, tc.challenge, tc.origin)
		w = loginFinishRequest(s, sid, body)
		require.Equal(t, 401, w.Code, tc.name+": "+w.Body.String())
		assert.JSONEq(t, `{"error":"`+loginFailureMessage+`"}`, w.Body.String())
		assert.Empty(t, w.Result().Cookies())
	}
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
