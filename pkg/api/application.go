package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nitrajka/al_ny/pkg/auth"
	"github.com/nitrajka/al_ny/pkg/db"
)

type app struct {
	db.Database
	auth                   auth.Authentication
	oauthGoogleURLAPI      string
	smtpConfig             *SMTPConfig
	resetPasswordClient    auth.Authentication
	resetPassTokenDuration time.Duration
}

type SMTPConfig struct {
	MailServiceUsername string
	MailServicePassword string
	From                string
	SMTPHost            string
	SMTPPort            string
}

func NewSMTPConfig(msu, msp, f, smtpHost, smtpPort string) *SMTPConfig {
	return &SMTPConfig{
		MailServiceUsername: msu,
		MailServicePassword: msp,
		From:                f,
		SMTPHost:            smtpHost,
		SMTPPort:            smtpPort,
	}
}

type Application interface {
	Login(c *gin.Context)
	Logout(c *gin.Context)
	Signup(c *gin.Context)
	GoogleLogin(c *gin.Context)
	UpdateUser(c *gin.Context)
	GetUserByID(c *gin.Context)
	PasswordReset(c *gin.Context)
	TokenAuthMiddleWare() gin.HandlerFunc
	ValidateToken(c *gin.Context)
	UpdatePassword(c *gin.Context)
	Test(c *gin.Context)
}

func NewApp(datab db.Database, aut auth.Authentication, config *SMTPConfig, rc auth.Authentication) (Application, error) {
	return &app{
		datab,
		aut,
		"https://www.googleapis.com/oauth2/v2/userinfo?access_token=",
		config,
		rc,
		time.Minute,
	}, nil
}
