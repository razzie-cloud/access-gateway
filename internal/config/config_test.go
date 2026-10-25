package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	prepareConfig(t)
	t.Setenv("POSTGRES_URI", "postgres://user:pass@localhost/gateway")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServicePort != 8080 || cfg.Origin != "http://localhost:8080" ||
		cfg.RPID != "localhost" || cfg.RPName != "Minimal WebAuthn" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
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
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ServicePort != 9090 || cfg.PostgresURI != values[1].value ||
				cfg.Origin != values[2].value || cfg.RPID != values[3].value || cfg.RPName != values[4].value {
				t.Fatalf("unexpected gateway settings: %+v", cfg)
			}
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
	if err := os.WriteFile(passwordFile, []byte("p@ss:word"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POSTGRES_PASSWORD_FILE", passwordFile)
	t.Setenv("REDIS_PASSWORD_FILE", passwordFile)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PostgresURI != "postgres://pguser:p%40ss%3Aword@db/gateway?sslmode=disable" {
		t.Fatalf("unexpected Postgres URI: %s", cfg.PostgresURI)
	}
	if cfg.RedisURI != "redis://redisuser:p%40ss%3Aword@redis:6379/0" {
		t.Fatalf("unexpected Redis URI: %s", cfg.RedisURI)
	}
}

func TestLoadRequiresPostgresURI(t *testing.T) {
	prepareConfig(t)
	cfg, err := Load()
	if cfg != nil || err == nil || !strings.Contains(err.Error(), "Postgres URI is required") {
		t.Fatalf("expected missing Postgres URI error, got config=%+v, err=%v", cfg, err)
	}
}
