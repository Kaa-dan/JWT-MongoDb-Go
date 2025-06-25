package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/kaa-dan/JWT-MongoDb-Go/routes"
)

func main() {

	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	router := gin.New()
	//logger middleware
	router.Use(gin.Logger())

	routes.AuthRoutes(router)

	routes.UserRoutes(router)

	router.GET("/api-1", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"success": "Access granted for api-1"})
	})
	router.GET("/api-2", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"success": "Access granted for api-2"})
	})

	router.Run(":" + port)
}
