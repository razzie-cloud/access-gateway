package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/razzie-cloud/access-gateway/internal/logging"
	"github.com/redis/go-redis/v9"
)

const assertionTTL = time.Minute
const signingPeriod = 24 * time.Hour
const keyOverlap = 2 * time.Minute
const assertionHeader = "X-Auth-Request-Token"

type assertionPublicKey struct {
	ID        string    `json:"kid"`
	PublicKey string    `json:"public_key"`
	NotBefore time.Time `json:"not_before"`
	ExpiresAt time.Time `json:"expires_at"`
}

type assertionKeySet struct {
	Issuer    string               `json:"issuer"`
	ExpiresAt time.Time            `json:"expires_at"`
	Keys      []assertionPublicKey `json:"keys"`
}

// KeyStore is supplied by Redis in production. Test servers use an isolated
// in-memory implementation; production never falls back when Redis fails.
type assertionKeyStore interface {
	assertionKey(context.Context, time.Time) (paseto.V4AsymmetricSecretKey, error)
}

// GET/reserve/absolute expiry is atomic and also works with Redis versions
// predating SET EXAT. Never overwrite a key another replica has published.
var reserveAssertionKey = redis.NewScript(`
local value = redis.call('GET', KEYS[1])
if value then return value end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('PEXPIREAT', KEYS[1], ARGV[2])
return redis.call('GET', KEYS[1])
`)

func (s *redisSessions) assertionKey(ctx context.Context, start time.Time) (paseto.V4AsymmetricSecretKey, error) {
	key := s.prefix + "paseto:" + strconv.FormatInt(start.Unix(), 10)
	raw, err := s.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		candidate := paseto.NewV4AsymmetricSecretKey()
		// Concurrent replicas propose independently; only the winner is used.
		raw, err = reserveAssertionKey.Run(ctx, s.client, []string{key}, candidate.ExportHex(), start.Add(signingPeriod+keyOverlap).UnixMilli()).Text()
	}
	if err != nil {
		return paseto.V4AsymmetricSecretKey{}, errors.New("signing key storage unavailable")
	}
	secret, err := paseto.NewV4AsymmetricSecretKeyFromHex(raw)
	if err != nil {
		return paseto.V4AsymmetricSecretKey{}, errors.New("invalid signing key record")
	}
	return secret, nil
}

func assertionKeyID(key paseto.V4AsymmetricPublicKey) string {
	sum := sha256.Sum256(key.ExportBytes())
	return hex.EncodeToString(sum[:16])
}

func (s *Server) assertionKeys(ctx context.Context, now time.Time) (assertionKeySet, error) {
	if s.assertions == nil {
		return assertionKeySet{}, errors.New("signing keys unavailable")
	}
	start := now.UTC().Truncate(signingPeriod)
	set := assertionKeySet{Issuer: s.cfg.Origin, ExpiresAt: now.Add(5 * time.Minute)}
	for _, offset := range []time.Duration{-signingPeriod, 0, signingPeriod} {
		begin := start.Add(offset)
		end := begin.Add(signingPeriod + keyOverlap)
		if !now.Before(end) {
			continue
		}
		secret, err := s.assertions.assertionKey(ctx, begin)
		if err != nil {
			return assertionKeySet{}, err
		}
		pub := secret.Public()
		set.Keys = append(set.Keys, assertionPublicKey{assertionKeyID(pub), pub.ExportHex(), begin, end})
	}
	return set, nil
}

func (s *Server) signIdentity(ctx context.Context, now time.Time, id, name, audience, method, uri string, admin bool) (string, error) {
	if s.assertions == nil {
		return "", errors.New("signing keys unavailable")
	}
	secret, err := s.assertions.assertionKey(ctx, now.UTC().Truncate(signingPeriod))
	if err != nil {
		return "", err
	}
	token := paseto.NewToken()
	token.SetIssuer(s.cfg.Origin)
	token.SetAudience(audience)
	token.SetSubject(id)
	token.SetString("name", name)
	token.SetString("method", method)
	token.SetString("uri", uri)
	_ = token.Set("admin", admin)
	token.SetIssuedAt(now)
	token.SetNotBefore(now)
	token.SetExpiration(now.Add(assertionTTL))
	// The footer selects a key, but becomes trusted only after verification.
	token.SetFooter([]byte(assertionKeyID(secret.Public())))
	return token.V4Sign(secret, nil), nil
}

func (s *Server) handleAssertionKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	set, err := s.assertionKeys(ctx, time.Now().UTC())
	if err != nil {
		logging.FailKind(r.Context(), slog.LevelError, "redis", "signing_keys")
		http.Error(w, "Signing keys unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(w, http.StatusOK, set)
}
