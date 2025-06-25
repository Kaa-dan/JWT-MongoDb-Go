package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kaa-dan/JWT-MongoDb-Go/controllers"
)

func AuthRoutes(r *gin.Engine) {
	r.POST("users/signup", controllers.Signup())
	r.POST("users/login", controllers.Login())
}
