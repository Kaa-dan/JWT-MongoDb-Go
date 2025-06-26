package middlewares

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/kaa-dan/JWT-MongoDb-Go/helpers"
)

// Authenticate validates JWT token and sets user context
func Authenticate() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Get token from Authorization header
		clientToken := c.Request.Header.Get("token")

		if clientToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "No Authorization header provided",
			})
			c.Abort()
			return
		}

		// Validate the token
		claims, err := helpers.ValidateToken(clientToken)
		if err != "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": fmt.Sprintf("Invalid token: %s", err),
			})
			c.Abort()
			return
		}

		// Set user context
		c.Set("email", claims.Email)
		c.Set("first_name", claims.First_name)
		c.Set("last_name", claims.Last_name)
		c.Set("uid", claims.Uid)
		c.Set("user_type", claims.User_type)

		// Continue to next handler
		c.Next()
	})
}
