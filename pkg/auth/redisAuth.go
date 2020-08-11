package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"time"
)

type redisClient struct {
	*redis.Client
	*tokenservice
}

func NewRedisAuthentication(address string) (Authentication, error) {
	client := redis.NewClient(&redis.Options{
		Addr: address,
	})
	_, err := client.Ping().Result()
	if err != nil {
		return nil, err
	}

	return &redisClient{client, NewTokenService()}, nil
}

func (rc redisClient) FetchAuth(c *gin.Context, key string) (string, error) { //authD *AccessDetails
	value, err := rc.Get(key).Result()
	if err != nil {
		return "", err
	}

	return value, nil
}

func (rc *redisClient) DeleteAuth(c *gin.Context, givenUuid string) (int64, error) {
	_, err := rc.Get(givenUuid).Result()
	if err == redis.Nil { // key does not exist in db
		return 0, nil
	}
	deleted, err := rc.Del(givenUuid).Result()
	if err != nil {
		return deleted, err
	}
	return deleted, nil
}

func (rc *redisClient) CreateAuth(c *gin.Context, key, value string) error { //userid uint64, td *AuthToken
	expire := time.Minute *15

	errAccess := rc.Set(key, value, expire).Err()
	if errAccess != nil {
		return errAccess
	}

	return nil
}
