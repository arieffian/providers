package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

type RedisService interface {
	SetCacheWithExpiration(ctx context.Context, key string, value interface{}, duration int) error
	SetCacheWithoutExpiration(ctx context.Context, key string, value interface{}) error
	GetCache(ctx context.Context, key string, result interface{}) error
	DeleteCache(ctx context.Context, key string) error
	Close(ctx context.Context) error
	Ping(ctx context.Context) *redis.StatusCmd
	Exists(ctx context.Context, key string) (bool, error)
	GetDefaultTTL(ctx context.Context) int
	GetKeysByPattern(ctx context.Context, pattern string) ([]string, error)
}

type RedisConfig struct {
	Host string
	Port int
	TTL  int
}

type RedisClient struct {
	ttl    int
	client *redis.Client
}

var _ RedisService = (*RedisClient)(nil)

func (r *RedisClient) SetCacheWithExpiration(ctx context.Context, key string, value interface{}, duration int) error {
	ttl := duration
	if ttl == 0 {
		ttl = r.ttl
	}

	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	log.Infof("[Redis][SetCacheWithExpiration] set cache with expiration with key: %s, ttl: %d", key, ttl)

	err = r.client.Set(ctx, key, jsonValue, time.Duration(ttl)*time.Minute).Err()
	if err != nil {
		log.Errorf("[Redis][SetCacheWithExpiration] error set cache with expiration with key: %s, ttl: %d, err: %v", key, ttl, err)
		return err
	}

	return nil
}

func (r *RedisClient) SetCacheWithoutExpiration(ctx context.Context, key string, value interface{}) error {
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	log.Infof("[Redis][SetCacheWithoutExpiration] set cache without expiration with key: %s", key)

	err = r.client.Set(ctx, key, jsonValue, 0).Err()
	if err != nil {
		log.Errorf("[Redis][SetCacheWithoutExpiration] error set cache without expiration with key: %s, err: %v", key, err)
		return err
	}

	return nil
}

func (r *RedisClient) GetCache(ctx context.Context, key string, result interface{}) error {
	log.Infof("[Redis][GetCache] get cache with key: %s", key)
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		log.Errorf("[Redis][GetCache] error get cache with key: %s, err: %v", key, err)
		return err
	}

	err = json.Unmarshal([]byte(val), result)
	if err != nil {
		log.Errorf("[Redis][GetCache] error unmarshal cache with key: %s, err: %v", key, err)
		return err
	}

	return nil
}

func (r *RedisClient) DeleteCache(ctx context.Context, key string) error {
	log.Infof("[Redis][DeleteCache] delete cache with key: %s", key)
	_, err := r.client.Del(ctx, key).Result()
	if err != nil {
		log.Errorf("[Redis][DeleteCache] error delete cache with key: %s, err: %v", key, err)
		return err
	}

	return nil
}

func (r *RedisClient) Close(ctx context.Context) error {
	log.Info("[Redis][Close] close redis connection")
	err := r.client.Close()
	if err != nil {
		log.Errorf("[Redis][Close] error close redis connection: %v", err)
		return err
	}

	return nil
}

func (r *RedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	res := r.client.Ping(ctx)
	return res
}

func (r *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	res, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	if res == 0 {
		return false, nil
	}

	return true, nil
}

func (r *RedisClient) GetDefaultTTL(ctx context.Context) int {
	return r.ttl
}

func (r *RedisClient) GetKeysByPattern(ctx context.Context, pattern string) ([]string, error) {
	res := []string{}
	iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		res = append(res, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func NewRedisConnection(cfg RedisConfig) *RedisClient {
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: "",
		DB:       0,
	})

	return &RedisClient{
		ttl:    cfg.TTL,
		client: rdb,
	}
}
