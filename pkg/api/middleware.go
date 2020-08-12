package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func (a *app) TokenAuthMiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		idS := c.Param("id")
		_, err := strconv.Atoi(idS)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "invalid user ID")
		}

		_, err = a.auth.FetchAuth(c, idS)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "Auth signature is invalid. Please, login correctly first.")
			c.Abort()
			return
		}
		c.Next()
	}
}
