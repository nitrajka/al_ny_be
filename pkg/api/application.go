package api

import (
	"github.com/gin-gonic/gin"
	"github.com/nitrajka/al_ny/pkg/auth"
	"github.com/nitrajka/al_ny/pkg/db"
	"time"
)

type app struct {
	db.Database
	auth auth.Authentication
	oauthGoogleUrlAPI string
	smtpConfig *SmtpConfig
	resetPasswordClient auth.Authentication
	resetPassTokenDuration time.Duration
}

type SmtpConfig struct {
	MailServiceUsername string
	MailServicePassword string
	From string
	SmtpHost string
	SmtpPort string
}

func NewSmtpConfig(msu, msp, f, smtpHost, smtpPort string) *SmtpConfig {
	return &SmtpConfig{
		MailServiceUsername: msu,
		MailServicePassword: msp,
		From:                f,
		SmtpHost:            smtpHost,
		SmtpPort:            smtpPort,
	}
}

type Application interface {
	Login(c *gin.Context)
	Logout(c *gin.Context)
	Signup(c *gin.Context)
	GoogleLogin(c *gin.Context)
	UpdateUser(c *gin.Context)
	GetUserById(c *gin.Context)
	PasswordReset(c *gin.Context)
	TokenAuthMiddleWare() gin.HandlerFunc
	ValidateToken(c *gin.Context)
	UpdatePassword(c *gin.Context)
	Test(c *gin.Context)
}

func NewApp(datab db.Database, aut auth.Authentication, config *SmtpConfig, rc auth.Authentication) (Application, error) {
	return &app{
		datab,
		aut,
		"https://www.googleapis.com/oauth2/v2/userinfo?access_token=",
		config,
		rc,
		time.Minute,
	}, nil
}
