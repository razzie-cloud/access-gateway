// Package brokerdiscovery implements bounded, secret-safe credential discovery.
// Keep the independent first-party service copies synchronized.
package brokerdiscovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var clientID = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var tokenValue = regexp.MustCompile(`^v1\.[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.[1-9][0-9]{0,15}\.[A-Za-z0-9_-]{43}$`)

type Options struct{ TokenFile, CAFile string }

func boundedFile(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("cannot open broker credential/trust file")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("invalid broker credential/trust file")
	}
	return b, nil
}
func prepare(raw string, options Options) (string, *http.Client, error) {
	bad := errors.New("invalid broker discovery configuration")
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", nil, bad
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil || len(q["client"]) > 1 || len(q["token"]) != 0 {
		return "", nil, bad
	}
	if len(q["client"]) == 1 && !clientID.MatchString(q.Get("client")) {
		return "", nil, bad
	}
	if options.TokenFile != "" {
		if len(q["client"]) != 1 {
			return "", nil, bad
		}
		b, e := boundedFile(options.TokenFile, 129)
		if e != nil {
			return "", nil, e
		}
		// Allow one text-file line terminator, never embedded or surrounding whitespace.
		token := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
		if len(token) > 128 || !tokenValue.MatchString(token) {
			return "", nil, errors.New("invalid broker token file")
		}
		q.Set("token", token)
	}
	u.RawQuery = q.Encode()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if options.CAFile != "" {
		b, e := boundedFile(options.CAFile, 1<<20)
		if e != nil {
			return "", nil, e
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(b) {
			return "", nil, errors.New("invalid broker CA file")
		}
		tlsConfig.RootCAs = roots
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = tlsConfig
	return u.String(), &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func Fetch(ctx context.Context, raw string, options Options) (string, error) {
	target, client, e := prepare(raw, options)
	if e != nil {
		return "", e
	}
	defer client.CloseIdleConnections()
	for attempt := range 5 {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if e != nil {
			return "", errors.New("invalid broker request")
		}
		resp, e := client.Do(req)
		if e == nil {
			b, readErr := io.ReadAll(io.LimitReader(resp.Body, 4097))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				if readErr != nil || len(b) > 4096 || len(b) == 0 {
					return "", errors.New("invalid broker response")
				}
				value := strings.TrimSpace(string(b))
				parsed, parseErr := url.Parse(value)
				if parseErr != nil || parsed.Host == "" || parsed.Fragment != "" || parsed.Opaque != "" || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" && parsed.Scheme != "redis" && parsed.Scheme != "rediss") {
					return "", errors.New("invalid broker credential URI")
				}
				return value, nil
			}
			if resp.StatusCode >= 300 && resp.StatusCode < 500 {
				return "", errors.New("broker rejected credential discovery")
			}
		}
		if attempt == 4 {
			break
		}
		timer := time.NewTimer(time.Duration(200*(1<<attempt)) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", errors.New("broker discovery canceled")
		case <-timer.C:
		}
	}
	return "", errors.New("broker discovery unavailable")
}
