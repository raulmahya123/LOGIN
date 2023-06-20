package controllers

import (
	"golangjwt-develop/database"
	helper "golangjwt-develop/helpers"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user") // membuat collection baru
var validate = validator.New()                                                          // membuat validator baru

func HashPassword()

func VerifyPassword()

func Signup()

func Login()

func GetUsers()

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("id")

		if err := helper.MatchUserTypeToUid(c, userId); err != nil { // memanggil helper MatchUserTypeToUid
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // jika error maka akan mengembalikan error
			return                                                     // mengembalikan error
		}
	}
}
