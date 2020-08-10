package auth

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/go-redis/redis"
)

type AuthToken struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	AccessUuid   string `json:"accessUuid"`
	RefreshUuid  string `json:"refreshUuid"`
	AtExpires    int64  `json:"atExpires"`
	RtExpires    int64  `json:"rtExpires"`
}

type AccessDetails struct {
	AccessUuid string `json:"accessUuid"`
	UserId     uint64 `json:"userId"`
}

type redisClient struct {
	*redis.Client
	*tokenservice
}

type Authentication interface {
	FetchAuth(authD *AccessDetails) (uint64, error)
	CreateAuth(userid uint64, td *AuthToken) error
	DeleteAuth(givenUuid string) (int64, error)
	DeleteRefresh(refreshUuid string) error
	DeleteTokens(authD *AccessDetails) error
	TokenInterface
}

func NewAuthentication(address string) (Authentication, error) {
	client := redis.NewClient(&redis.Options{
		Addr: address,
	})
	_, err := client.Ping().Result()
	if err != nil {
		return nil, err
	}

	return &redisClient{client, NewTokenService()}, nil
}

func (rc redisClient) FetchAuth(authD *AccessDetails) (uint64, error) {
	userid, err := rc.Get(authD.AccessUuid).Result()
	if err != nil {
		return 0, err
	}
	userID, _ := strconv.ParseUint(userid, 10, 64)
	return userID, nil
}

func (rc *redisClient) DeleteAuth(givenUuid string) (int64, error) {
	deleted, err := rc.Del(givenUuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func (rc *redisClient) CreateAuth(userid uint64, td *AuthToken) error {
	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := rc.Set(td.AccessUuid, strconv.Itoa(int(userid)), at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := rc.Set(td.RefreshUuid, strconv.Itoa(int(userid)), rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

func (rc *redisClient) DeleteTokens(authD *AccessDetails) error {
	//get the refresh uuid
	refreshUuid := fmt.Sprintf("%s++%s", authD.AccessUuid, authD.UserId)
	//delete access token
	deletedAt, err := rc.Del(authD.AccessUuid).Result()
	if err != nil {
		return err
	}
	//delete refresh token
	deletedRt, err := rc.Del(refreshUuid).Result()
	if err != nil {
		return err
	}
	//When the record is deleted, the return value is 1
	if deletedAt != 1 || deletedRt != 1 {
		return errors.New("something went wrong")
	}
	return nil
}

func (rc *redisClient) DeleteRefresh(refreshUuid string) error {
	//delete refresh token
	deleted, err := rc.Del(refreshUuid).Result()
	if err != nil || deleted == 0 {
		return err
	}
	return nil
}
