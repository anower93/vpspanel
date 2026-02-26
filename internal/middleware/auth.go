package middleware

import (
	"net/http"
	"vpspanel/internal/services"

	"github.com/gin-gonic/gin"
)

func Setup(r *gin.Engine, auth *services.AuthService) {
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
}

func AuthRequired(auth *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := auth.GetSession(c.Request)
		if session == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Set("session", session)
		c.Next()
	}
}
