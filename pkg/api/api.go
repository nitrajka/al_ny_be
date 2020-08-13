package api

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/nitrajka/al_ny/pkg/auth"
	"github.com/nitrajka/al_ny/pkg/db"
	"github.com/twinj/uuid"
	"io/ioutil"
	"net/http"
	"net/smtp"
	"strconv"
	"time"
)

type UserServer struct {
	app Application
	*gin.Engine
}

func NewUserServer(app Application) (*UserServer, error) {
	us := new(UserServer)
	us.app = app

	router := gin.Default()

	router.GET("/test", app.Test)
	router.POST("/login", app.Login)
	router.POST("/login/google", app.GoogleLogin)
	router.POST("/logout", app.Logout)
	router.POST("/signup", app.Signup)

	router.GET("/user/:id", app.TokenAuthMiddleWare(), app.GetUserById)
	router.PUT("/user/:id", app.TokenAuthMiddleWare(), app.UpdateUser)

	router.POST("/password/reset", app.PasswordReset)
	router.POST("/password/reset/validate", app.ValidateToken)
	router.POST("/password/renew", app.UpdatePassword)

	us.Engine = router
	return us, nil
}

func (a *app) Test(c *gin.Context) {
	c.JSON(http.StatusOK, "")
}

func (a *app) Login(c *gin.Context) {
	var cred db.Credentials
	if err := c.ShouldBindJSON(&cred); err != nil {
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("expected username and password")))
		return
	}

	// cannot login with empty credentials
	if cred.Username == "" || cred.Password == "" {
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("fields must not be empty")))
		return
	}

	//find user and compare user
	user, exists, err := a.Database.UserExistsByCredentials(cred)
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("database error %v", err)))
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, NotFoundUserError("email", cred.Username))
		return
	}

	if user.SignedUpWithGoogle {
		c.JSON(http.StatusConflict, InvalidLoginType(nil))
		return
	}

	if !db.CheckPasswordHash(cred.Password, user.Password)  {
		c.JSON(http.StatusUnauthorized, IncorrectPasswordError(fmt.Errorf(user.Username)))
		return
	}

	token, err := a.auth.CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("could not create auth token")))
		return
	}

	err = a.auth.CreateAuth(c, strconv.Itoa(int(user.ID)), token.AccessUuid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("could not create auth token")))
	}

	c.Header("HttpOnly", "True")
	resp := db.SignUpResponse{
		Token: token.AccessToken,
		User:  *db.DBUserToUser(*user),
	}
	c.JSON(http.StatusOK, resp)
}

func (a *app) Logout(c *gin.Context) {
	var id uint64
	if err := c.ShouldBindJSON(&id); err != nil {
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("must provide user ID in body")))
		return
	}

	user, err := a.Database.GetUserById(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, InternalServerError(fmt.Errorf("cannot logout non existent user")))
		return
	}

	if user.SignedUpWithGoogle {
		_, err = a.auth.DeleteAuth(c, strconv.Itoa(int(user.ID)))
		c.JSON(http.StatusOK, nil)
		return
	}

	ad, err := a.auth.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
		return
	}

	if ad.UserId != user.ID {
		c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
		return
	}

	deleted, err := a.auth.DeleteAuth(c, strconv.Itoa(int(user.ID)))
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("could not logout")))
		return
	}

	if deleted == 0 {
		c.JSON(http.StatusOK, "already logged out")
		return
	}

	c.JSON(http.StatusOK, "successfully logged out")
}

func (a *app) Signup(c *gin.Context) {
	var cred db.Credentials
	if err := c.ShouldBindJSON(&cred); err != nil {
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("must provide username and password")))
		return
	}

	if cred.Username == "" || cred.Password == "" {
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("fields must not be empty")))
		return
	}

	u, exists, err := a.Database.UserExistsByCredentials(cred)
	if err != nil {
		c.JSON(http.StatusBadRequest, NotFoundUserError("email", strconv.Itoa(int(u.ID))))
		return
	}

	if exists && u.SignedUpWithGoogle {
		c.JSON(http.StatusConflict, InvalidLoginType(fmt.Errorf("such user already signed up with google")))
		return
	} else if exists {
		c.JSON(http.StatusConflict, UserAlreadyExists(fmt.Errorf(u.Username)))
		return
	}

	u = db.NewUser(cred.Username, cred.Password, "", "", "", false)
	u, err = a.Database.CreateUser(u)
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("database error")))
		return
	}

	token, err := a.auth.CreateToken(u.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("could not create auth token")))
		return
	}

	saveErr := a.auth.CreateAuth(c, strconv.Itoa(int(u.ID)), token.AccessUuid)
	if saveErr != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("could not create auth token")))
		return
	}

	c.Header("HttpOnly", "True")
	c.JSON(http.StatusCreated, db.SignUpResponse{
		Token: token.AccessToken,
		User: *db.DBUserToUser(*u),
	})
}

func (a *app) GoogleLogin(c *gin.Context) {
	token := auth.ExtractToken(c.Request)

	response, err := http.Get(a.oauthGoogleUrlAPI + token)
	if err != nil {
		c.JSON(http.StatusUnauthorized,
			UnauthorizedError(fmt.Errorf("could not validate google token, please sign up again")))
		return
	}

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			InternalServerError(fmt.Errorf("could not validate google token, please log in again later")))
		return
	}

	var gr *db.GoogleResponse
	err = json.Unmarshal(contents, &gr)
	if err != nil {
		c.JSON(http.StatusUnauthorized,
			UnauthorizedError(fmt.Errorf("could not validate google token, please sign up again")))
		return
	}

	if !gr.VerifiedEmail {
		c.JSON(http.StatusUnauthorized,
			UnauthorizedError(fmt.Errorf("could not validate google token, please sign up again")))
		return
	}

	//save user to db + convert user to response format
	dbUser := &db.DBUser{
		ID:                 0,
		Credentials:        db.Credentials{Username: gr.Email},
		FullName:           "",
		Phone:              "",
		Address:            "",
		SignedUpWithGoogle: true,
	}

	u, exists, err := a.Database.UserExistsByCredentials(db.Credentials{Username: gr.Email})
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("database error %v", err)))
		return
	}

	if exists {
		if !u.SignedUpWithGoogle {
			c.JSON(http.StatusBadRequest, InvalidLoginType(nil))
			return
		}

		t, err := a.auth.FetchAuth(c, strconv.Itoa(int(u.ID)))
		if err != nil { // user is not authenticated, but exists
			err = a.auth.CreateAuth(c, strconv.Itoa(int(u.ID)), token)
			if err != nil {
				c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("could not create auth token")))
				return
			}

			resp := &db.SignUpResponse{
				Token: token,
				User:  *db.DBUserToUser(*u),
			}

			c.JSON(http.StatusOK, resp)
			return
		}

		t = t.(string)
		if t != token {
			c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
			return
		}

		resp := &db.SignUpResponse{
			Token: token,
			User:  *db.DBUserToUser(*u),
		}

		c.JSON(http.StatusOK, resp)
		return
	}

	us, err := a.Database.CreateUser(dbUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("database error %v", err)))
		return
	}
	dbUser = us

	err = a.auth.CreateAuth(c, strconv.Itoa(int(dbUser.ID)), token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("could not create auth token")))
		return
	}

	resp := &db.SignUpResponse{
		Token: token,
		User:  *db.DBUserToUser(*dbUser),
	}

	c.JSON(http.StatusOK, resp)
}

func (a *app) GetUserById(c *gin.Context) {
	idS := c.Param("id")
	id, err := strconv.Atoi(idS)
	if err != nil {
		c.JSON(http.StatusBadRequest, InvalidPathParam(fmt.Errorf("user id should be a number")))
		return
	}

	u, err := a.Database.GetUserById(uint64(id))
	if err != nil {
		c.JSON(http.StatusBadRequest, NotFoundUserError("ID", fmt.Sprintf("%v. database error %v", u.ID, err)))
		return
	}

	if u.SignedUpWithGoogle {
		savedToken, err := a.auth.FetchAuth(c, idS)
		if err != nil {
			c.JSON(http.StatusUnauthorized, UnauthorizedError(err))
			return
		}
		savedToken = savedToken.(string)

		token := auth.ExtractToken(c.Request)
		if token != savedToken {
			c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
			return
		}

		c.JSON(http.StatusOK, db.DBUserToUser(*u))
		return
	}

	tokenAuth, err := a.auth.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
		return
	}

	accessUuid, err := a.auth.FetchAuth(c, strconv.Itoa(int(tokenAuth.UserId)))
	if err != nil {
		c.JSON(http.StatusUnauthorized, UnauthorizedError(err))
		return
	}
	accessUuid = accessUuid.(string)

	if accessUuid != tokenAuth.AccessUuid || uint64(id) != tokenAuth.UserId {
		c.JSON(http.StatusUnauthorized,  UnauthorizedError(nil))
		return
	}

	c.JSON(http.StatusOK, db.DBUserToUser(*u))
}

func (a *app) UpdateUser(c *gin.Context) {
	idS := c.Param("id")
	id, err := strconv.Atoi(idS)
	if err != nil {
		c.JSON(http.StatusBadRequest, InvalidPathParam(fmt.Errorf("user id should be a number")))
		return
	}

	user, err := a.Database.GetUserById(uint64(id))
	if err != nil {
		c.JSON(http.StatusBadRequest, NotFoundUserError("ID", fmt.Sprintf("%v, %v", idS, err)))
		return
	}

	if user.SignedUpWithGoogle {
		savedToken, err := a.auth.FetchAuth(c, idS)
		if err != nil {
			c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
			return
		}
		savedToken = savedToken.(string)

		token := auth.ExtractToken(c.Request)
		if token != savedToken {
			c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
			return
		}

		var u *db.UpdateUserBodyGoogleSigned
		if err := c.ShouldBindJSON(&u); err != nil {
			c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("expected fullname, phone, and address")))
			return
		}

		user.FullName = u.FullName
		user.Address = u.Address
		user.Phone = u.Phone

		newUser, err := a.Database.UpdateUser(db.DBUserToUpdateUserBody(*user), uint64(id))
		if err != nil {
			c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("could not update user, database error: %v", err)))
			return
		}


		c.JSON(http.StatusOK, db.DBUserToUser(*newUser))
		return
	}

	tokenAuth, err := a.auth.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
		return
	}

	accessUuid, err := a.auth.FetchAuth(c, strconv.Itoa(int(tokenAuth.UserId)))
	if err != nil {
		c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
		return
	}
	accessUuid = accessUuid.(string)

	if accessUuid != tokenAuth.AccessUuid || uint64(id) != tokenAuth.UserId {
		c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
		return
	}

	var u *db.UpdateUserBody
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("expected username, fullname, phone, and address")))
		return
	}

	newUser, err := a.Database.UpdateUser(u, uint64(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("could not update user: %v", err)))
		return
	}

	c.JSON(http.StatusOK, db.DBUserToUser(*newUser))
}

func (a *app) PasswordReset(c *gin.Context) {
	var payload struct {Email string `json:"email"`; Redirect string `json:"redirect"`}
	if err := c.ShouldBindJSON(&payload); err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("email address and redirectUrl expected")))
		return
	}

	u, exists, err := a.Database.UserExistsByCredentials(db.Credentials{Username: payload.Email})
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("could not validate user")))
		return
	}

	if !exists {
		c.JSON(http.StatusBadRequest, InternalServerError(fmt.Errorf("user does not exist")))
		return
	}

	if u.SignedUpWithGoogle {
		c.JSON(http.StatusBadRequest, InternalServerError(fmt.Errorf("cannot reset password of this user")))
		return
	}

	token := uuid.NewV4().String()

	err = a.resetPasswordClient.CreateAuth(c, payload.Email, []string{token, time.Now().Format(time.RFC3339)})
	if err != nil {
		c.JSON(http.StatusInternalServerError, InternalServerError(err))
	}

	creds := smtp.PlainAuth("", a.smtpConfig.MailServiceUsername, a.smtpConfig.MailServicePassword,
		a.smtpConfig.SmtpHost)
	msg := []byte("To: " + payload.Email + "\r\n" +
		"Subject: Reset Password\r\n" +
		"\r\n" +
		"Hi,\r\n " +
		"use the following link to reset password. Link will be invalid in 15 minutes.\r\n" +
		payload.Redirect + token + "/" + payload.Email +" \r\n")

	err = smtp.SendMail(a.smtpConfig.SmtpHost + ":" + a.smtpConfig.SmtpPort, creds,
			a.smtpConfig.From, []string{payload.Email}, msg)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			InternalServerError(fmt.Errorf("sorry, could not send email: %v", err)))
		return
	}

	c.JSON(http.StatusOK, "email sent successfully")
}

func (a *app) ValidateToken(c *gin.Context) {
	var payload struct {Token string `json:"token"`; Email string `json:"email"`}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("email address and redirectUrl expected")))
		return
	}

	savedTokenInfo, err := a.resetPasswordClient.FetchAuth(c, payload.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ResetPasswordError(err))
		return
	}

	tokenInfo := savedTokenInfo.([]string)
	if tokenInfo[0] != payload.Token {
		c.JSON(http.StatusUnauthorized, ResetPasswordError(fmt.Errorf("unauthorized to update other's password")))
		return
	}

	if tm, _ := time.Parse(time.RFC3339, tokenInfo[1]); time.Now().Sub(tm) > a.resetPassTokenDuration {
		c.JSON(http.StatusUnauthorized, ResetPasswordError(fmt.Errorf("link already invalid")))
		return
	}

	c.JSON(http.StatusOK, "tokenValid")
}

func (a *app) UpdatePassword(c *gin.Context) {
	var payload struct {Mail string `json:"username"`; Password string `json:"password"`; Token string `json:"token"`}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("email address and redirectUrl expected")))
		return
	}

	savedTokenInfo, err := a.resetPasswordClient.FetchAuth(c, payload.Mail)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ResetPasswordError(err))
		return
	}

	tokenInfo := savedTokenInfo.([]string)
	if tokenInfo[0] != payload.Token {
		c.JSON(http.StatusUnauthorized, ResetPasswordError(fmt.Errorf("unauthorized to update other's password")))
		return
	}

	if tm, _ := time.Parse(time.RFC3339, tokenInfo[1]); time.Now().Sub(tm) > a.resetPassTokenDuration {
		c.JSON(http.StatusUnauthorized, ResetPasswordError(fmt.Errorf("link already invalid")))
		return
	}

	deleted, err := a.resetPasswordClient.DeleteAuth(c, payload.Mail)
	if err != nil {
		c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
		return
	}

	if deleted == 0 {
		c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
		return
	}

	err = a.Database.ResetPassword(db.Credentials{Username: payload.Mail, Password: payload.Password})
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			InternalServerError(fmt.Errorf("could not update password: %s", err.Error())))
		return
	}

	c.JSON(http.StatusOK, "password successfully updated")
}