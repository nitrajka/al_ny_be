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
)

type UserServer struct {
	app Application
	*gin.Engine
}

func NewUserServer(app Application) (*UserServer, error) {
	us := new(UserServer)
	us.app = app

	router := gin.Default()

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
		c.JSON(http.StatusInternalServerError, InternalServerError(fmt.Errorf("database error")))
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, NotFoundUserError(fmt.Errorf(strconv.Itoa(int(user.ID)))))
		return
	}

	if user.SignedUpWithGoogle {
		c.JSON(http.StatusConflict, InvalidLoginType(nil))
		return
	}

	if !db.CheckPasswordHash(cred.Password, user.Password)  {
		c.JSON(http.StatusUnauthorized, IncorrectPasswordError(fmt.Errorf(strconv.Itoa(int(user.ID)))))
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
		c.JSON(http.StatusBadRequest, NotFoundUserError(fmt.Errorf(strconv.Itoa(int(u.ID)))))
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
		c.JSON(http.StatusBadRequest, NotFoundUserError(fmt.Errorf("database error")))
		return
	}

	if u.SignedUpWithGoogle {
		savedToken, err := a.auth.FetchAuth(c, idS)
		if err != nil {
			c.JSON(http.StatusUnauthorized, UnauthorizedError(err))
			return
		}

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
		c.JSON(http.StatusBadRequest, NotFoundUserError(fmt.Errorf("cannot update non existent user")))
		return
	}

	if user.SignedUpWithGoogle {
		savedToken, err := a.auth.FetchAuth(c, idS)
		if err != nil {
			c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
			return
		}

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
	var body struct {link string `json:"redirectUrl"`; email string `json:"email"`}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("email address and redirectUrl expected")))
		return
	}

	fmt.Println(body)

	u, exists, err := a.Database.UserExistsByCredentials(db.Credentials{Username: body.email})
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

	creds := smtp.PlainAuth("", a.smtpConfig.MailServiceUsername, a.smtpConfig.MailServicePassword,
		a.smtpConfig.SmtpHost)


	token := uuid.NewV4().String()
	err = SaveResetToken(c, a.resetPasswordClient, body.email, token)

	// Here we do it all: connect to our server, set up a message and send it
	msg := []byte("To: " + body.email + "\r\n" +
		"Subject: Reset Password\r\n" +
		"\r\n" +
		"Hi,\r\n " +
		"use the following link to reset password. Link will be invalid in 15 minutes.\r\n" +
		body.link + token +" \r\n")

	err = smtp.SendMail(a.smtpConfig.SmtpHost + ":" + a.smtpConfig.SmtpPort, creds, a.smtpConfig.From, []string{body.email}, msg)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			InternalServerError(fmt.Errorf("sorry, could not send email: %v", err)))
		return
	}

	c.JSON(http.StatusOK, "email sent successfully")
}

func (a *app) ValidateToken(c *gin.Context) {
	var payload struct {token string `json:"token"`; email string `json:"email"`}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("email address and redirectUrl expected")))
		return
	}

	savedToken, err := FetchResetToken(c, a.resetPasswordClient, payload.email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ResetPasswordError(err))
		return
	}

	if savedToken != payload.token {
		c.JSON(http.StatusUnauthorized, ResetPasswordError(fmt.Errorf("unauthorized to update other's password")))
		return
	}

	c.JSON(http.StatusOK, "tokenValid")
}

func (a *app) UpdatePassword(c *gin.Context) {
	var payload struct {mail string `json:"username"`; password string `json:"password"`; token string `json:"token"`}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, InvalidBodyError(fmt.Errorf("email address and redirectUrl expected")))
		return
	}

	savedToken, err := FetchResetToken(c, a.resetPasswordClient, payload.mail)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ResetPasswordError(err))
		return
	}

	if savedToken != payload.token {
		c.JSON(http.StatusUnauthorized, ResetPasswordError(fmt.Errorf("unauthorized to update other's password")))
		return
	}

	deleted, err := DeleteResetToken(c, a.resetPasswordClient, payload.mail)
	if err != nil {
		c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
		return
	}

	if deleted == 0 {
		c.JSON(http.StatusUnauthorized, UnauthorizedError(nil))
		return
	}

	err = a.Database.ResetPassword(db.Credentials{Username: payload.mail,Password: payload.password})
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			InternalServerError(fmt.Errorf("could not update password: %s", err.Error())))
		return
	}

	c.JSON(http.StatusOK, "password successfully updated")
}