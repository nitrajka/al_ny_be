package auth

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

type sessionClient struct {
	sessionsStore *sessions.CookieStore
	session *sessions.Session
	*tokenservice
	sessionName string
}

func NewSessionAuth(key []byte, sessionName string) Authentication {
	store := sessions.NewCookieStore(key)
	return &sessionClient{
		sessionsStore: store,
		session: sessions.NewSession(store, sessionName),
		tokenservice: NewTokenService(),
	}
}

func (sc *sessionClient) FetchAuth(c *gin.Context, key string) (interface{}, error) {
	fmt.Println(sc.session.Values)
	if value, ok := sc.session.Values[key]; ok {
		return value, nil
	}

	return "", errors.New("session does not exist")
}

func (sc *sessionClient) CreateAuth(c *gin.Context, key string, value interface{}) error {
	sc.session.Values[key] = value

	err := sc.session.Save(c.Request, c.Writer)
	if err != nil {
		return err
	}

	return nil
}

func (sc *sessionClient) DeleteAuth(c *gin.Context, key string) (int64, error) {
	delete(sc.session.Values, key)

	err := sc.session.Save(c.Request, c.Writer)
	if err != nil {
		return 0, err
	}
	return 1, nil
}
