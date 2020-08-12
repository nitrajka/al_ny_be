package api

import (
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"time"
)

func NewRedisClient(address string) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr: address,
	})
	_, err := client.Ping().Result()
	if err != nil {
		return nil, err
	}

	return client, nil
}

func FetchResetToken(c *gin.Context, rc *redis.Client, key string) (string, error) { //authD *AccessDetails
	value, err := rc.Get(key).Result()
	if err != nil {
		return "", err
	}

	return value, nil
}

func DeleteResetToken(c *gin.Context, rc *redis.Client, key string) (int64, error) {
	_, err := rc.Get(key).Result()
	if err == redis.Nil { // key does not exist in db
		return 0, nil
	}
	deleted, err := rc.Del(key).Result()
	if err != nil {
		return deleted, err
	}
	return deleted, nil
}

func SaveResetToken(c *gin.Context, rc *redis.Client, key, value string) error { //userid uint64, td *AuthToken
	expire := time.Minute *15

	errAccess := rc.Set(key, value, expire).Err()
	if errAccess != nil {
		return errAccess
	}

	return nil
}
