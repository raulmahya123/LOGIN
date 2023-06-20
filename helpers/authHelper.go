package helpers

import (
	"errors"

	"github.com/gin-gonic/gin"
)

func CheckUserType(c *gin.Context, role string) (err error) { // membuat fungsi CheckUserType
	userType := c.GetString("user_type")
	err = nil
	if userType != role {
		err = errors.New("Unauthorized")
		return err // jika userType tidak sama dengan role
	}
	return err // mengambil user_type dari context
}
func MatchUserTypeToUid(c *gin.Context, userId string) (err error) { // membuat fungsi MatchUserTypeToUid
	userType := c.GetString("user_type") // mengambil uid dari context
	uid := c.GetString("uid")

	err = nil
	if userType == "USER" && uid != userId {
		err = errors.New("Unauthorized") // jika uid tidak sama dengan userId
		return err
	}
	CheckUserType(c, userType)
	return err // jika uid tidak sama dengan userId
}
