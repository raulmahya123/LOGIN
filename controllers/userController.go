package controllers

import (
	"golangjwt-develop/database"

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

func GetUser()
