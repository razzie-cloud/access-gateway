package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"

	"github.com/redis/go-redis/v9"
)

var beginAppFlow = redis.NewScript(`
local now = redis.call('TIME')
local millis = now[1]*1000 + math.floor(now[2]/1000)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', millis)
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[4]) then return 0 end
if not redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2]) then return 0 end
redis.call('ZADD', KEYS[2], millis+tonumber(ARGV[2]), ARGV[3])
redis.call('PEXPIRE', KEYS[2], ARGV[2])
return 1
`)

func (s *redisSessions) beginAppLogin(ctx context.Context, origin, returnTo string) (string, string, error) {
	flow, state := rand.Text(), rand.Text()
	payload, _ := json.Marshal(redisFlow{Origin: origin, ReturnTo: returnTo, StateHash: hashToken(state)})
	ok, err := beginAppFlow.Run(ctx, s.client, []string{s.key("flow", flow), s.prefix + "flows"}, payload, appLoginTTL.Milliseconds(), hashToken(flow), maxAppLoginFlows).Int()
	if err != nil {
		return "", "", sessionStoreError(err)
	}
	if ok != 1 {
		return "", "", sessionStoreError(errors.New("too many pending sign-ins"))
	}
	return flow, state, nil
}

func (s *redisSessions) appLogin(ctx context.Context, flowID string) (appLoginFlow, bool, error) {
	flow, ok, err := getSession[redisFlow](ctx, s, s.key("flow", flowID))
	return appLoginFlow{origin: flow.Origin, returnTo: flow.ReturnTo}, ok, err
}

var authorizeAppFlow = redis.NewScript(`
local ttl = math.min(redis.call('PTTL', KEYS[1]), redis.call('PTTL', KEYS[2]), tonumber(ARGV[2]))
if ttl <= 0 then return 0 end
if not redis.call('SET', KEYS[3], ARGV[1], 'NX', 'PX', ttl) then return 0 end
return 1
`)

func (s *redisSessions) authorizeAppLogin(ctx context.Context, flowID, parent string) (string, bool, error) {
	code := rand.Text()
	payload, _ := json.Marshal(redisGrant{Flow: hashToken(flowID), Parent: hashToken(parent)})
	result, err := authorizeAppFlow.Run(ctx, s.client, []string{s.key("flow", flowID), s.key("auth", parent), s.key("grant", code)}, payload, appCodeTTL.Milliseconds()).Int()
	if err != nil {
		return "", false, sessionStoreError(err)
	}
	if result != 1 {
		return "", false, nil
	}
	return code, true, nil
}

var completeAppFlow = redis.NewScript(`
local rawFlow = redis.call('GET', KEYS[1])
local rawGrant = redis.call('GET', KEYS[2])
local ttl = redis.call('PTTL', KEYS[3])
if not rawFlow or not rawGrant or ttl <= 0 then return nil end
local flow = cjson.decode(rawFlow)
local grant = cjson.decode(rawGrant)
if flow.Origin ~= ARGV[1] or flow.StateHash ~= ARGV[2] or grant.Flow ~= ARGV[3] or grant.Parent ~= ARGV[4] then return nil end
if not redis.call('SET', KEYS[4], ARGV[5], 'NX', 'PX', ttl) then return nil end
redis.call('DEL', KEYS[1], KEYS[2])
redis.call('ZREM', KEYS[5], ARGV[3])
return flow.ReturnTo
`)

func (s *redisSessions) completeAppLogin(ctx context.Context, flowID, code, state, origin string) (string, string, bool, error) {
	grant, ok, err := getSession[redisGrant](ctx, s, s.key("grant", code))
	if err != nil || !ok {
		return "", "", false, err
	}
	token := rand.Text()
	payload, _ := json.Marshal(redisApp{Origin: origin, Parent: grant.Parent})
	keys := []string{s.key("flow", flowID), s.key("grant", code), s.prefix + "auth:" + grant.Parent, s.key("app", token), s.prefix + "flows"}
	returnTo, err := completeAppFlow.Run(ctx, s.client, keys, origin, hashToken(state), hashToken(flowID), grant.Parent, payload).Text()
	if errors.Is(err, redis.Nil) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, sessionStoreError(err)
	}
	s.cache.delete(keys[0], keys[1])
	return token, returnTo, true, nil
}

func (s *redisSessions) getAppAuth(ctx context.Context, token, origin string) (string, bool, error) {
	app, ok, err := getSession[redisApp](ctx, s, s.key("app", token))
	if err != nil || !ok {
		return "", false, err
	}
	if app.Origin != origin {
		return "", false, nil
	}
	parent, ok, err := getSession[redisAuth](ctx, s, s.prefix+"auth:"+app.Parent)
	return parent.Username, ok, err
}
