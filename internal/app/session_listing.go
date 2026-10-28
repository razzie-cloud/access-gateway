package app

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// ListSessions scans this gateway's namespace, including sessions from other
// replicas. SCAN avoids blocking Redis and sees pre-existing sessions without
// maintaining a separate index. The result is a snapshot, not an audit log.
func (s *redisSessions) ListSessions(ctx context.Context) ([]sessionSummary, error) {
	var sessions []sessionSummary
	seen := make(map[string]bool)
	for _, kind := range []string{"auth", "app"} {
		var cursor uint64
		for {
			keys, next, err := s.client.Scan(ctx, cursor, s.prefix+kind+":*", 100).Result()
			if err != nil {
				return nil, sessionStoreError(err)
			}
			for _, key := range keys {
				// SCAN can return a key more than once while Redis changes.
				if seen[key] {
					continue
				}
				seen[key] = true
				record, expires, ok, err := s.sessionMetadata(ctx, key)
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
				summary := sessionSummary{ID: strings.TrimPrefix(key, s.prefix+kind+":"), Kind: "Gateway", Username: record.Username, ExpiresAt: expires, DeviceID: record.DeviceID}
				if kind == "app" {
					parent, parentExpires, live, err := s.sessionMetadata(ctx, s.prefix+"auth:"+record.Parent)
					if err != nil {
						return nil, err
					}
					// Logout invalidates app sessions even before their keys expire.
					if !live {
						continue
					}
					summary.Kind, summary.Username, summary.Origin = "Application", parent.Username, record.Origin
					summary.DeviceID, summary.ParentID = parent.DeviceID, record.Parent
					if parentExpires.Before(summary.ExpiresAt) {
						summary.ExpiresAt = parentExpires
					}
				}
				sessions = append(sessions, summary)
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
	}
	sort.Slice(sessions, func(i, j int) bool {
		a, b := sessions[i], sessions[j]
		if a.Username != b.Username {
			return a.Username < b.Username
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.ID < b.ID
	})
	return sessions, nil
}

// Read only identity metadata directly from Redis, with an atomic payload/TTL
// read. Never use cached records to list expired or revoked sessions.
type sessionMetadata struct {
	Username, Origin, Parent string
	DeviceID                 int64
}

func (s *redisSessions) sessionMetadata(ctx context.Context, key string) (record sessionMetadata, expires time.Time, ok bool, err error) {
	started := time.Now()
	values, err := readLiveSession.Run(ctx, s.client, []string{key}).Slice()
	if errors.Is(err, redis.Nil) {
		return record, expires, false, nil
	}
	if err != nil {
		return record, expires, false, sessionStoreError(err)
	}
	if len(values) != 2 {
		return record, expires, false, sessionStoreError(errors.New("invalid session record"))
	}
	payload, validPayload := values[0].(string)
	ttl, validTTL := values[1].(int64)
	if !validPayload || !validTTL || ttl <= 0 {
		return record, expires, false, sessionStoreError(errors.New("invalid session metadata"))
	}
	if err := json.Unmarshal([]byte(payload), &record); err != nil {
		return record, expires, false, sessionStoreError(errors.New("invalid session JSON"))
	}
	expires = started.Add(time.Duration(ttl) * time.Millisecond)
	return record, expires, time.Now().Before(expires), nil
}

func (s *redisSessions) DeleteSession(ctx context.Context, kind, id string) error {
	if !validSessionID(id) || (kind != "Gateway" && kind != "Application") {
		return sessionStoreError(errors.New("invalid session reference"))
	}
	prefix := "auth:"
	if kind == "Application" {
		prefix = "app:"
	}
	key := s.prefix + prefix + id
	s.cache.delete(key)
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return sessionStoreError(err)
	}
	return nil
}
