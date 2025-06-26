package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kaa-dan/JWT-MongoDb-Go/helpers"
	"github.com/kaa-dan/JWT-MongoDb-Go/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// GetUsers retrieves all users (Admin only)
func GetUsers() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Check if user is admin
		if err := helpers.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		// Get pagination parameters
		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}

		page, err := strconv.Atoi(c.Query("page"))
		if err != nil || page < 1 {
			page = 1
		}

		startIndex := (page - 1) * recordPerPage
		startIndex, err = strconv.Atoi(c.Query("startIndex"))

		// Create aggregation pipeline
		matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}
		groupStage := bson.D{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
			{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
			{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
		}}}
		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}},
			}},
		}

		// Execute aggregation
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, groupStage, projectStage,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Error occurred while listing user items",
			})
			return
		}

		var allUsers []bson.M
		if err = result.All(ctx, &allUsers); err != nil {
			log.Fatal(err)
		}

		// Return users data
		if len(allUsers) > 0 {
			c.JSON(http.StatusOK, gin.H{
				"total_count": allUsers[0]["total_count"],
				"users":       allUsers[0]["user_items"],
				"page":        page,
				"per_page":    recordPerPage,
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"total_count": 0,
				"users":       []interface{}{},
				"page":        page,
				"per_page":    recordPerPage,
			})
		}
	})
}

// GetUser retrieves a single user by ID
func GetUser() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		userId := c.Param("user_id")

		// Check if user is authorized to access this user data
		if err := helpers.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User

		// Find user by user_id
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		// Remove sensitive information before sending response
		user.Password = nil
		user.Token = nil
		user.Refresh_token = nil

		// Return user data
		c.JSON(http.StatusOK, gin.H{
			"user": user,
		})
	})
}

// UpdateUser updates user information
func UpdateUser() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		userId := c.Param("user_id")

		// Check if user is authorized to update this user data
		if err := helpers.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var updateUser models.User

		// Bind JSON request to user struct
		if err := c.BindJSON(&updateUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Create update document
		var updateObj primitive.D

		if updateUser.First_name != nil {
			updateObj = append(updateObj, bson.E{Key: "first_name", Value: updateUser.First_name})
		}

		if updateUser.Last_name != nil {
			updateObj = append(updateObj, bson.E{Key: "last_name", Value: updateUser.Last_name})
		}

		if updateUser.Email != nil {
			// Check if email already exists for another user
			count, err := userCollection.CountDocuments(ctx, bson.M{
				"email":   updateUser.Email,
				"user_id": bson.M{"$ne": userId},
			})
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Error occurred while checking email",
				})
				return
			}
			if count > 0 {
				c.JSON(http.StatusConflict, gin.H{
					"error": "Email already exists",
				})
				return
			}
			updateObj = append(updateObj, bson.E{Key: "email", Value: updateUser.Email})
		}

		if updateUser.Phone != nil {
			// Check if phone already exists for another user
			count, err := userCollection.CountDocuments(ctx, bson.M{
				"phone":   updateUser.Phone,
				"user_id": bson.M{"$ne": userId},
			})
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Error occurred while checking phone",
				})
				return
			}
			if count > 0 {
				c.JSON(http.StatusConflict, gin.H{
					"error": "Phone number already exists",
				})
				return
			}
			updateObj = append(updateObj, bson.E{Key: "phone", Value: updateUser.Phone})
		}

		if updateUser.Password != nil {
			// Hash the new password
			hashedPassword := HashPassword(*updateUser.Password)
			updateObj = append(updateObj, bson.E{Key: "password", Value: hashedPassword})
		}

		// Set updated timestamp
		updatedAt, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		updateObj = append(updateObj, bson.E{Key: "updated_at", Value: updatedAt})

		// Update the user
		upsert := false
		opt := options.UpdateOptions{
			Upsert: &upsert,
		}

		result, err := userCollection.UpdateOne(
			ctx,
			bson.M{"user_id": userId},
			bson.D{{Key: "$set", Value: updateObj}},
			&opt,
		)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "User update failed",
			})
			return
		}

		if result.MatchedCount == 0 {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "User updated successfully",
		})
	})
}

// DeleteUser deletes a user (Admin only)
func DeleteUser() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		userId := c.Param("user_id")

		// Check if user is admin
		if err := helpers.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		// Delete the user
		result, err := userCollection.DeleteOne(ctx, bson.M{"user_id": userId})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Error occurred while deleting user",
			})
			return
		}

		if result.DeletedCount == 0 {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("User %s deleted successfully", userId),
		})
	})
}
