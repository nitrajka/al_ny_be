package auth

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/twinj/uuid"
	"net/http"
	"os"
	"strconv"
)

type tokenservice struct{}

func NewTokenService() *tokenservice {
	return &tokenservice{}
}

type TokenInterface interface {
	CreateToken(userId uint64) (*AuthToken, error)
	ExtractTokenMetadata(*http.Request) (*AccessDetails, error)
}

func (t *tokenservice) CreateToken(ID uint64) (*AuthToken, error) {
	var err error

	td := &AuthToken{}
	td.AccessUuid = uuid.NewV4().String()

	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = ID
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return &AuthToken{}, err
	}

	return td, nil
}

func (t *tokenservice) ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}

		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &AccessDetails{
			AccessUuid: accessUuid,
			UserId:     userId,
		}, nil
	}
	return nil, errors.New("could not decode claims from token")
}

func ParseTokenAndVerifyMethod(tokenString, secret string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New(fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}
		return []byte(secret), nil
	})

	return token, err
}

func ExtractToken(r *http.Request) string {
	res := r.Header.Get("Authorization")
	if len(res) > 0 && res[len(res)-1] == ',' {
		return res[:len(res)-1]
	}

	return res
}

func IsTokenValid(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	token, err := ParseTokenAndVerifyMethod(tokenString, os.Getenv("ACCESS_SECRET"))
	if err != nil {
		return nil, err
	}
	return token, nil
}