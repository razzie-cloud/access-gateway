// Package healthcheck provides the shell-free container readiness probe.
package healthcheck

import (
	"net"
	"net/http"
	"os"
	"time"
)

func port() string {
	p := os.Getenv("SERVICE_PORT")
	if p == "" {
		p = "8080"
	}
	return p
}

// Run returns a process exit code without loading service configuration or secrets.
func Run() int {
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port()) + "/readyz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
