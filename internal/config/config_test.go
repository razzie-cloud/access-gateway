package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func prepareConfig(t *testing.T, args ...string) {
	t.Helper()
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = append([]string{"access-gateway"}, args...)
	for _, key := range []string{
		"SERVICE_PORT", "ORIGIN", "RP_ID", "RP_NAME",
		"POSTGRES_URI", "POSTGRES_URI_FROM", "POSTGRES_PASSWORD_FILE",
		"REDIS_URI", "REDIS_URI_FROM", "REDIS_PASSWORD_FILE",
	} {
		t.Setenv(key, "")
		require.NoError(t, os.Unsetenv(key))
	}
}

func TestLoadDefaults(t *testing.T) {
	prepareConfig(t)
	t.Setenv("POSTGRES_URI", "postgres://user:pass@localhost/gateway")
	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, 8080, cfg.ServicePort)
	assert.Equal(t, "http://localhost:8080", cfg.Origin)
	assert.Equal(t, "localhost", cfg.RPID)
	assert.Equal(t, "Minimal WebAuthn", cfg.RPName)
}

func TestLoadGatewaySettings(t *testing.T) {
	for _, fromArgs := range []bool{false, true} {
		t.Run(fmt.Sprintf("fromArgs=%t", fromArgs), func(t *testing.T) {
			prepareConfig(t)
			values := []struct{ env, flag, value string }{
				{"SERVICE_PORT", "--port", "9090"},
				{"POSTGRES_URI", "--postgres-uri", "postgres://user:pass@db/gateway"},
				{"ORIGIN", "--origin", "https://login.example.com"},
				{"RP_ID", "--rp-id", "example.com"},
				{"RP_NAME", "--rp-name", "Gateway"},
			}
			for _, v := range values {
				if fromArgs {
					// CLI settings must override the environment.
					t.Setenv(v.env, "1")
					os.Args = append(os.Args, v.flag, v.value)
				} else {
					t.Setenv(v.env, v.value)
				}
			}
			cfg, err := Load()
			require.NoError(t, err)
			require.NotNil(t, cfg)
			assert.Equal(t, 9090, cfg.ServicePort)
			assert.Equal(t, values[1].value, cfg.PostgresURI)
			assert.Equal(t, values[2].value, cfg.Origin)
			assert.Equal(t, values[3].value, cfg.RPID)
			assert.Equal(t, values[4].value, cfg.RPName)
		})
	}
}

func TestLoadBrokerURIsAndPasswordFiles(t *testing.T) {
	prepareConfig(t)
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/instances/postgres/gateway/uri":
			fmt.Fprint(w, "postgres://pguser@db/gateway?sslmode=disable")
		case "/v1/instances/redis/gateway/uri":
			fmt.Fprint(w, "redis://redisuser@redis:6379/0")
		default:
			http.NotFound(w, r)
		}
	}))
	defer broker.Close()
	t.Setenv("POSTGRES_URI", "postgres://unused/old")
	t.Setenv("REDIS_URI", "redis://unused/0")
	t.Setenv("POSTGRES_URI_FROM", broker.URL+"/v1/instances/postgres/gateway/uri")
	t.Setenv("REDIS_URI_FROM", broker.URL+"/v1/instances/redis/gateway/uri")
	passwordFile := filepath.Join(t.TempDir(), "password")
	require.NoError(t, os.WriteFile(passwordFile, []byte("p@ss:word"), 0600))
	t.Setenv("POSTGRES_PASSWORD_FILE", passwordFile)
	t.Setenv("REDIS_PASSWORD_FILE", passwordFile)
	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "postgres://pguser:p%40ss%3Aword@db/gateway?sslmode=disable", cfg.PostgresURI)
	assert.Equal(t, "redis://redisuser:p%40ss%3Aword@redis:6379/0", cfg.RedisURI)
}

func TestLoadRequiresPostgresURI(t *testing.T) {
	prepareConfig(t)
	cfg, err := Load()
	assert.Nil(t, cfg)
	assert.ErrorContains(t, err, "Postgres URI is required")
}
