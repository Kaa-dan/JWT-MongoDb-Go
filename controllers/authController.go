package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/kaa-dan/JWT-MongoDb-Go/database"
	"github.com/kaa-dan/JWT-MongoDb-Go/helpers"
	"github.com/kaa-dan/JWT-MongoDb-Go/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection
var validate = validator.New()

// InitializeAuthController initializes the package variables after DB connection
func InitializeAuthController() {
	userCollection = database.GetCollection("users")
}

// HashPassword hashes the password using bcrypt
func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

// VerifyPassword compares hashed password with plain text password
func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("Email or password is incorrect")
		check = false
	}

	return check, msg
}

// Signup creates a new user account
func Signup() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Ensure initialization
		if userCollection == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Database not initialized",
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User

		// Bind JSON request to user struct
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Validate the user struct
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": validationErr.Error(),
			})
			return
		}

		// Check if user already exists by email
		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Error occurred while checking for the email",
			})
			return
		}

		// Check if user already exists by phone
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Error occurred while checking for the phone number",
			})
			return
		}

		if count > 0 {
			c.JSON(http.StatusConflict, gin.H{
				"error": "This email or phone number already exists",
			})
			return
		}

		// Hash the password
		password := HashPassword(*user.Password)
		user.Password = &password

		// Set user timestamps and ID
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()

		// Generate JWT tokens
		token, refreshToken, _ := helpers.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, user.User_id)
		user.Token = &token
		user.Refresh_token = &refreshToken

		// Insert user into database
		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": msg,
			})
			return
		}

		// Return success response
		c.JSON(http.StatusOK, gin.H{
			"message":       "User created successfully",
			"user_id":       resultInsertionNumber.InsertedID,
			"token":         token,
			"refresh_token": refreshToken,
		})
	})
}

// Login authenticates a user and returns JWT tokens
func Login() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Ensure initialization
		if userCollection == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Database not initialized",
			})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		var foundUser models.User

		// Bind JSON request to user struct
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Find user by email
		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Email or password is incorrect",
			})
			return
		}

		// Verify password
		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		if !passwordIsValid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": msg,
			})
			return
		}

		// Check if user exists
		if foundUser.Email == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not found",
			})
			return
		}

		// Generate new JWT tokens
		token, refreshToken, _ := helpers.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, foundUser.User_id)

		// Update tokens in database
		helpers.UpdateAllTokens(token, refreshToken, foundUser.User_id)

		// Find updated user
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Return success response
		c.JSON(http.StatusOK, gin.H{
			"message":       "Login successful",
			"user_id":       foundUser.User_id,
			"email":         foundUser.Email,
			"first_name":    foundUser.First_name,
			"last_name":     foundUser.Last_name,
			"user_type":     foundUser.User_type,
			"token":         token,
			"refresh_token": refreshToken,
		})
	})
}
