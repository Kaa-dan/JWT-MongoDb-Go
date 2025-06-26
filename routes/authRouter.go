package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kaa-dan/JWT-MongoDb-Go/controllers"
)

func AuthRoutes(r *gin.Engine) {
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/signup", controllers.Signup()) //POST /auth/signup  - create new user
		authGroup.POST("/login", controllers.Login())   // POST /auth/login  - login already existing user
	}
}
