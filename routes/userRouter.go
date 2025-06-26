package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/kaa-dan/JWT-MongoDb-Go/controllers"
	"github.com/kaa-dan/JWT-MongoDb-Go/middlewares"
)

func UserRoutes(r *gin.Engine) {
	// Create a route group with authentication middleware
	userGroup := r.Group("/users")
	userGroup.Use(middlewares.Authenticate())
	{
		userGroup.GET("/", controllers.GetUsers())              // GET /users - Get all users (Admin only)
		userGroup.GET("/:user_id", controllers.GetUser())       // GET /users/:user_id - Get user by ID
		userGroup.PUT("/:user_id", controllers.UpdateUser())    // PUT /users/:user_id - Update user
		userGroup.DELETE("/:user_id", controllers.DeleteUser()) // DELETE /users/:user_id - Delete user (Admin only)
	}
}
