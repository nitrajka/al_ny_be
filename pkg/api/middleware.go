package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nitrajka/al_ny/pkg/auth"
)

func TokenAuthMiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := auth.IsTokenValid(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "signature is invalid")
			c.Abort()
			return
		}
		c.Next()
	}
}
