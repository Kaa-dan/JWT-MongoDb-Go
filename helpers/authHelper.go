package helpers

import (
	"errors"

	"github.com/gin-gonic/gin"
)

// CheckUserType checks if the user has the required user type
func CheckUserType(c *gin.Context, role string) (err error) {
	userType := c.GetString("user_type")
	err = nil

	if userType != role {
		err = errors.New("unauthorized to access this resource")
		return err
	}

	return err
}

// MatchUserTypeToUid checks if the user type matches or if the user is accessing their own data
func MatchUserTypeToUid(c *gin.Context, userId string) (err error) {
	userType := c.GetString("user_type")
	uid := c.GetString("uid")
	err = nil

	// Admin can access any user's data
	if userType == "ADMIN" {
		return err
	}

	// Regular user can only access their own data
	if userType == "USER" && uid == userId {
		return err
	}

	err = errors.New("unauthorized to access this resource")
	return err
}
