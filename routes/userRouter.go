package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kaa-dan/JWT-MongoDb-Go/controllers"
	"github.com/kaa-dan/JWT-MongoDb-Go/middlewares"
)

func UserRoutes(r *gin.Engine) {
	r.Use(middlewares.Authenticate())

	r.GET("/users", controllers.GetUsers())
	r.GET("/users/:user_id", controllers.GetUser())
}
