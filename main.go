package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/kaa-dan/JWT-MongoDb-Go/controllers"
	"github.com/kaa-dan/JWT-MongoDb-Go/database"
	"github.com/kaa-dan/JWT-MongoDb-Go/helpers"
	"github.com/kaa-dan/JWT-MongoDb-Go/routes"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Connect to MongoDB
	database.ConnectDB()

	// Initialize package-level variables after DB connection
	helpers.InitializeTokenHelper()
	controllers.InitializeAuthController()
	controllers.InitializeUserController()

	// Set Gin mode based on environment
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	router := gin.New()

	// Add middlewares
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Add CORS middleware for production
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, token")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Setup routes
	routes.AuthRoutes(router)
	routes.UserRoutes(router)

	// Health check endpoint
	router.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"message": "JWT Authentication API is running",
		})
	})

	log.Printf("Starting server on port %s", port)
	router.Run(":" + port)
}
