package db

import (
	"context"
	"github.com/go-redis/redis/v8"
	"time"
)

type RedisDatabase struct {
	Client *redis.Client
}

var RedisDb *RedisDatabase

var (
	Ctx = context.TODO()
)

func NewDatabase(address string) error {
	client := redis.NewClient(&redis.Options{
		Addr:     address,
		Password: "",
		DB:       0,
	})
	if err := client.Ping(Ctx).Err(); err != nil {
		return err
	}
	RedisDb = &RedisDatabase{
		Client: client,
	}
	return nil
}

func GetRedisDb() *RedisDatabase {
	return RedisDb
}

func (rdb RedisDatabase) GetByKey(key string) (string, error) {
	return rdb.Client.Get(Ctx, key).Result()
}

func (rdb RedisDatabase) SetKey(key string, value string, exp time.Duration) *redis.StatusCmd {
	return rdb.Client.Set(Ctx, key, value, exp)
}

func (rdb RedisDatabase) DelById(key string) (int64, error) {
	return rdb.Client.Del(Ctx, key).Result()
}
