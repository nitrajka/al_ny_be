package api

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/nitrajka/al_ny/pkg/auth"
	"github.com/nitrajka/al_ny/pkg/db"
	"io/ioutil"
	"net/http"
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

	us.Engine = router
	return us, nil
}

//--------------------------------------------------------------------
// userId + token -> porovnat token
// userId + accessId -> porovnat

func (a *app) Login(c *gin.Context) {
	var cred db.Credentials
	if err := c.ShouldBindJSON(&cred); err != nil {
		c.JSON(http.StatusBadRequest, "Provided invalid JSON.")
		return
	}

	// cannot login with empty credentials
	if cred.Username == "" || cred.Password == "" {
		c.JSON(http.StatusBadRequest, "fields must not be empty")
		return
	}

	//find user and compare user
	user, exists, err := a.Database.UserExistsByCredentials(cred)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	if !exists {
		c.JSON(http.StatusNotFound, "such user does not exist")
		return
	}

	if user.SignedUpWithGoogle {
		c.JSON(http.StatusConflict, "please use the kind of login you used while registration")
		return
	}

	if !db.CheckPasswordHash(cred.Password, user.Password)  {
		c.JSON(http.StatusUnauthorized, "incorrect password for this user")
		return
	}

	token, err := a.auth.CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	err = a.auth.CreateAuth(c, strconv.Itoa(int(user.ID)), token.AccessUuid)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
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
		c.JSON(http.StatusUnprocessableEntity, "must provide user ID in body") // todo fe
		return
	}

	user, err := a.Database.GetUserById(id)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, "cannot logout non existent user") // todo fe
		return
	}

	if user.SignedUpWithGoogle {
		_, err = a.auth.DeleteAuth(c, strconv.Itoa(int(user.ID)))
		return
	}

	ad, err := a.auth.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, "unauthorized")
		return
	}

	if ad.UserId != user.ID {
		c.JSON(http.StatusUnauthorized, "cannot logout different user")
		return
	}

	deleted, err := a.auth.DeleteAuth(c, strconv.Itoa(int(user.ID)))
	if err != nil {
		c.JSON(http.StatusInternalServerError, "unauthorized")
		return
	}

	if deleted == 0 {
		c.JSON(http.StatusUnprocessableEntity, "already logged out")
		return
	}

	c.JSON(http.StatusOK, "successfully logged out")
}

func (a *app) Signup(c *gin.Context) {
	var cred db.Credentials
	if err := c.ShouldBindJSON(&cred); err != nil {
		c.JSON(http.StatusBadRequest, "Provided invalid JSON.")
		return
	}

	if cred.Username == "" || cred.Password == "" {
		c.JSON(http.StatusBadRequest, "fields must not be empty")
		return
	}

	u, exists, err := a.Database.UserExistsByCredentials(cred)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
		return
	}

	if exists && u.SignedUpWithGoogle {
		c.JSON(http.StatusConflict, "such user already signed up with google")
		return
	} else if exists {
		c.JSON(http.StatusConflict, "such username already exists")
		return
	}

	u = db.NewUser(cred.Username, cred.Password, "", "", "", false)
	u, err = a.Database.CreateUser(u)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "user was not created")
		return
	}

	token, err := a.auth.CreateToken(u.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	saveErr := a.auth.CreateAuth(c, strconv.Itoa(int(u.ID)), token.AccessUuid)
	if saveErr != nil {
		c.JSON(http.StatusInternalServerError, "could not create auth token")
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
		c.JSON(http.StatusUnauthorized, "could not validate google token, please sign up again")
		return
	}

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	var gr *db.GoogleResponse
	err = json.Unmarshal(contents, &gr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	if !gr.VerifiedEmail {
		c.JSON(http.StatusUnauthorized, "unauthorized")
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
	us, err := a.Database.CreateUser(dbUser)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	err = a.auth.CreateAuth(c, strconv.Itoa(int(us.ID)), token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "unauthorized")
		return
	}

	resp := &db.SignUpResponse{
		Token: token,
		User:  *db.DBUserToUser(*us),
	}

	c.JSON(http.StatusOK, resp)
}

//--------------------------------------------------------------------------
func (a *app) GetUserById(c *gin.Context) {
	idS := c.Param("id")

	id, err := strconv.Atoi(idS)

	u, err := a.Database.GetUserById(uint64(id))
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	if u.SignedUpWithGoogle {
		savedToken, err := a.auth.FetchAuth(c, idS)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "unauthorized")
			return
		}

		token := auth.ExtractToken(c.Request)
		if token != savedToken {
			c.JSON(http.StatusUnauthorized, "unauthorized")
			return
		}

		c.JSON(http.StatusOK, db.DBUserToUser(*u))
		return
	}

	tokenAuth, err := a.auth.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	accessUuid, err := a.auth.FetchAuth(c, strconv.Itoa(int(tokenAuth.UserId)))
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	if accessUuid != tokenAuth.AccessUuid || uint64(id) != tokenAuth.UserId {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	c.JSON(http.StatusOK, db.DBUserToUser(*u))
}

func (a *app) UpdateUser(c *gin.Context) {
	idS := c.Param("id")

	id, err := strconv.Atoi(idS)

	user, err := a.Database.GetUserById(uint64(id))
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	if user.SignedUpWithGoogle {
		savedToken, err := a.auth.FetchAuth(c, idS)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "unauthorized")
			return
		}

		token := auth.ExtractToken(c.Request)
		if token != savedToken {
			c.JSON(http.StatusUnauthorized, "unauthorized")
			return
		}

		c.JSON(http.StatusOK, db.DBUserToUser(*user))
		return
	}


	tokenAuth, err := a.auth.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	accessUuid, err := a.auth.FetchAuth(c, strconv.Itoa(int(tokenAuth.UserId)))
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	if accessUuid != tokenAuth.AccessUuid || uint64(id) != tokenAuth.UserId {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	var u *db.UpdateUserBody
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}

	newUser, err := a.Database.UpdateUser(u, uint64(id))
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, "could not update:" + err.Error())
		return
	}

	c.JSON(http.StatusOK, db.DBUserToUser(*newUser))
}