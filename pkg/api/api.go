package api

import (
	"github.com/gin-gonic/gin"
	"github.com/nitrajka/al_ny/pkg/auth"
	"github.com/nitrajka/al_ny/pkg/db"
	"net/http"
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
	router.POST("/logout", app.Logout)
	router.POST("/signup", app.Signup)

	router.GET("/user", TokenAuthMiddleWare(), app.GetUserById)
	router.PUT("/user", TokenAuthMiddleWare(), app.UpdateUser)

	us.Engine = router
	return us, nil
}

type app struct {
	db.Database
	auth auth.Authentication
}

type Application interface {
	Login(c *gin.Context)
	Logout(c *gin.Context)
	Signup(c *gin.Context)
	UpdateUser(c *gin.Context)
	GetUserById(c *gin.Context)
}

func NewApp(datab db.Database, aut auth.Authentication) (Application, error) {
	return &app{
		datab,
		aut,
	}, nil
}

//--------------------------------------------------------------------
func (a *app) Login(c *gin.Context) {
	var cred db.Credentials
	if err := c.ShouldBindJSON(&cred); err != nil {
		c.JSON(http.StatusBadRequest, "Provided invalid JSON.")
		return
	}

	if cred.Username == "" || cred.Password == "" {
		c.JSON(http.StatusBadRequest, "fields must not be empty")
		return
	}

	//find user and compare user
	user, exists := a.Database.UserExistsByCredentials(cred)
	if !exists {
		c.JSON(http.StatusNotFound, "such user does not exist")
		return
	}

	if user.Password != cred.Password {
		c.JSON(http.StatusUnauthorized, "incorrect password for this user")
		return
	}

	if user.SignedUpWithGoogle {
		c.JSON(http.StatusConflict, "please use the kind of login you used while registration")
		return
	}

	token, err := a.auth.CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	saveErr := a.auth.CreateAuth(user.ID, token)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
	}

	c.Header("HttpOnly", "True")
	resp := db.SignUpResponse{
		Token: token.AccessToken,
		User:  *db.DBUserToUser(*user),
	}
	c.JSON(http.StatusOK, resp)
}

func (a *app) Logout(c *gin.Context) {
	au, err := a.auth.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, "unauthorized")
		return
	}

	deleted, err := a.auth.DeleteAuth(au.AccessUuid)
	if err != nil || deleted == 0 {
		c.JSON(http.StatusUnprocessableEntity, "already logged out or unauthorized")
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

	_, exists := a.Database.UserExistsByCredentials(cred)
	if exists {
		c.JSON(http.StatusConflict, "such username already exists")
		return
	}

	u := db.NewUser(cred.Username, cred.Password, "", "", "", false)
	u, err := a.Database.CreateUser(u)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "user was not created")
		return
	}

	token, err := a.auth.CreateToken(u.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	saveErr := a.auth.CreateAuth(u.ID, token)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
		return
	}

	c.Header("HttpOnly", "True")
	c.JSON(http.StatusCreated, db.SignUpResponse{
		Token: token.AccessToken,
		User: *db.DBUserToUser(*u),
	})
}

//--------------------------------------------------------------------------
func (a *app) GetUserById(c *gin.Context) {
	tokenAuth, err := a.auth.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	userId, err := a.auth.FetchAuth(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	u, err := a.Database.GetUserById(userId)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "user does not exist")
		return
	}

	c.JSON(http.StatusOK, db.DBUserToUser(*u))
}

func (a *app) UpdateUser(c *gin.Context) {
	tokenAuth, err := a.auth.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	userId, err := a.auth.FetchAuth(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}

	var u *db.UpdateUserBody
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}

	if userId != u.ID {
		c.JSON(http.StatusUnauthorized, "cannot update different user")
		return
	}

	newUser, err := a.Database.UpdateUser(u)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, "could not update")
		return
	}

	c.JSON(http.StatusOK, db.DBUserToUser(*newUser))
}