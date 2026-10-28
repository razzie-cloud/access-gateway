package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

type redisSessions struct {
	client *redis.Client
	prefix string
	cache  *sessionCache
}

type redisRegistration struct {
	Registration registrationContext
	Data         webauthn.SessionData
}

type redisLogin struct {
	Username string
	Data     webauthn.SessionData
}

type redisAuth struct {
	Username string
	DeviceID int64
}
type redisApp struct{ Origin, Parent string }
type redisFlow struct{ Origin, ReturnTo, StateHash string }
type redisGrant struct{ Flow, Parent string }

func newRedisSessions(uri, namespace string) (*redisSessions, error) {
	if uri == "" {
		return nil, errors.New("Redis URI is required: set REDIS_URI or REDIS_URI_FROM")
	}
	opts, err := redis.ParseURL(uri)
	if err != nil {
		return nil, errors.New("invalid Redis URI")
	}
	opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = 2*time.Second, 2*time.Second, 2*time.Second
	opts.ContextTimeoutEnabled = true
	// Non-idempotent script responses must never be replayed automatically.
	opts.MaxRetries = -1
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect to Redis: %w", err)
	}
	return &redisSessions{client: client, prefix: "access-gateway:v1:{" + hashToken(namespace) + "}:", cache: newSessionCache()}, nil
}

func (s *redisSessions) Close() error { return s.client.Close() }
func (s *redisSessions) key(kind, token string) string {
	return s.prefix + kind + ":" + hashToken(token)
}
func sessionStoreError(err error) error { return fmt.Errorf("%w: %v", errSessionStore, err) }

var readLiveSession = redis.NewScript(`
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return nil end
return {redis.call('GET', KEYS[1]), ttl}
`)

func getSession[T any](ctx context.Context, s *redisSessions, key string) (T, bool, error) {
	var zero T
	if cached, ok := s.cache.get(key); ok {
		// Every authorization checks Redis, including cache hits. Cross-replica
		// logout, eviction, expiry and outages can never be masked by local data.
		ttl, err := s.client.PTTL(ctx, key).Result()
		if err != nil {
			s.cache.delete(key)
			return zero, false, sessionStoreError(err)
		}
		if ttl <= 0 {
			s.cache.delete(key)
			return zero, false, nil
		}
		return cached.(T), true, nil
	}
	started := time.Now()
	values, err := readLiveSession.Run(ctx, s.client, []string{key}).Slice()
	if errors.Is(err, redis.Nil) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, sessionStoreError(err)
	}
	if len(values) != 2 {
		return zero, false, sessionStoreError(errors.New("invalid session record"))
	}
	payload, ok := values[0].(string)
	if !ok {
		return zero, false, sessionStoreError(errors.New("invalid session payload"))
	}
	ttl, ok := values[1].(int64)
	if !ok || ttl <= 0 {
		return zero, false, sessionStoreError(errors.New("invalid session expiry"))
	}
	var value T
	if err := json.Unmarshal([]byte(payload), &value); err != nil {
		return zero, false, sessionStoreError(errors.New("invalid session JSON"))
	}
	expires := started.Add(min(time.Duration(ttl)*time.Millisecond, sessionCacheTTL))
	if time.Now().Before(expires) {
		s.cache.put(key, value, expires)
	}
	return value, true, nil
}

func (s *redisSessions) put(ctx context.Context, key string, value any, ttl time.Duration) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return sessionStoreError(err)
	}
	ok, err := s.client.SetNX(ctx, key, payload, ttl).Result()
	if err != nil {
		return sessionStoreError(err)
	}
	if !ok {
		return sessionStoreError(errors.New("session token already exists"))
	}
	return nil
}

func (s *redisSessions) PutRegistration(ctx context.Context, sid string, registration registrationContext, data webauthn.SessionData) error {
	return s.put(ctx, s.key("registration", sid), redisRegistration{registration, data}, ceremonyTTL)
}
func (s *redisSessions) GetRegistration(ctx context.Context, sid string) (registrationContext, webauthn.SessionData, bool, error) {
	v, ok, err := getSession[redisRegistration](ctx, s, s.key("registration", sid))
	return v.Registration, v.Data, ok, err
}
func (s *redisSessions) PutLogin(ctx context.Context, sid, username string, data webauthn.SessionData) error {
	return s.put(ctx, s.key("login", sid), redisLogin{username, data}, ceremonyTTL)
}
func (s *redisSessions) GetLogin(ctx context.Context, sid string) (string, webauthn.SessionData, bool, error) {
	v, ok, err := getSession[redisLogin](ctx, s, s.key("login", sid))
	return v.Username, v.Data, ok, err
}
func (s *redisSessions) PutAuth(ctx context.Context, token, username string) error {
	return s.put(ctx, s.key("auth", token), redisAuth{Username: username}, authTTL)
}
func (s *redisSessions) GetAuth(ctx context.Context, token string) (string, bool, error) {
	v, ok, err := getSession[redisAuth](ctx, s, s.key("auth", token))
	return v.Username, ok, err
}
func (s *redisSessions) DeleteAuth(ctx context.Context, token string) error {
	key := s.key("auth", token)
	s.cache.delete(key)
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return sessionStoreError(err)
	}
	return nil
}
func (s *redisSessions) DeleteSID(ctx context.Context, sid string) error {
	keys := []string{s.key("registration", sid), s.key("login", sid)}
	s.cache.delete(keys...)
	if err := s.client.Del(ctx, keys...).Err(); err != nil {
		return sessionStoreError(err)
	}
	return nil
}

var finishLogin = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
if not raw or redis.call('PTTL', KEYS[1]) <= 0 then return 0 end
if cjson.decode(raw).Username ~= ARGV[1] then return 0 end
if not redis.call('SET', KEYS[2], ARGV[2], 'NX', 'PX', ARGV[3]) then return 0 end
redis.call('DEL', KEYS[1], KEYS[3])
return 1
`)

func (s *redisSessions) CompleteLogin(ctx context.Context, sid, token, username string, deviceID int64) (bool, error) {
	payload, _ := json.Marshal(redisAuth{Username: username, DeviceID: deviceID})
	keys := []string{s.key("login", sid), s.key("auth", token), s.key("registration", sid)}
	result, err := finishLogin.Run(ctx, s.client, keys, username, payload, authTTL.Milliseconds()).Int()
	s.cache.delete(keys[0], keys[2])
	if err != nil {
		return false, sessionStoreError(err)
	}
	return result == 1, nil
}
