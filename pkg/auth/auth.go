package auth

import "github.com/gin-gonic/gin"

type AuthToken struct {
	AccessToken string `json:"accessToken"`
	AccessUuid  string `json:"accessUuid"`
}

type AccessDetails struct {
	AccessUuid string `json:"accessUuid"`
	UserId     uint64 `json:"userId"`
}

type Authentication interface {
	FetchAuth(c *gin.Context, key string) (interface{}, error)      //*AccessDetails
	CreateAuth(c *gin.Context, key string, value interface{}) error //userid uint64, td *AuthToken
	DeleteAuth(c *gin.Context, givenUuid string) (int64, error)
	TokenInterface
}
