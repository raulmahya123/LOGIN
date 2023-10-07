package controllers

import (
	"context"
	"crypto/rand"
	"fmt"
	"golangjwt-develop/database"
	"golangjwt-develop/models"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	helper "golangjwt-develop/helpers"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	"github.com/o1egl/paseto/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user") // membuat collection baru
// Validation instance
var validate = validator.New()

// HashPassword hashes the plain password
func HashPassword(password string) string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) { // membuat fungsi VerifyPassword
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""
	if err != nil {
		msg = fmt.Sprintln("Password doesn't match")
		check = false
	}
	return check, msg // jika password tidak sama dengan providedPassword
}

// Generate a random PASETO secret key
func generatePasetoKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Generate a random JWT secret key
func generateJWTKey() ([]byte, error) {
	key := make([]byte, 64) // You can adjust the key size as needed
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Signup function
func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		validateErr := validate.Struct(user)
		if validateErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validateErr.Error()})
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred"})
			return
		}

		password := HashPassword(*user.Password)
		user.Password = &password

		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred"})
			return
		}

		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email already exists"})
			return
		}

		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		userID := user.ID.Hex()
		user.User_id = &userID

		// Generate PASETO secret key
		pasetoSecret, err := generatePasetoKey()
		if err != nil {
			log.Printf("Error generating PASETO key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate PASETO key"})
			return
		}

		// Generate token PASETO
		tokenClaims := paseto.JSONToken{
			Subject:    *user.User_id,
			Expiration: time.Now().Add(24 * time.Hour),
		}

		pasetoToken, err := paseto.NewV2().Encrypt(pasetoSecret, tokenClaims, nil)
		if err != nil {
			log.Printf("Error generating PASETO token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate PASETO token"})
			return
		}

		user.Paseto_token = &pasetoToken

		// Generate JWT secret key
		jwtSecret, err := generateJWTKey()
		if err != nil {
			log.Printf("Error generating JWT key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate JWT key"})
			return
		}

		// Generate token JWT
		tokenClaimsJWT := jwt.MapClaims{
			"email":      *user.Email,
			"first_name": *user.First_name,
			"last_name":  *user.Last_name,
			"uid":        *user.User_id,
			"user_type":  *user.User_type,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaimsJWT)
		jwtToken, err := token.SignedString(jwtSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate JWT token"})
			return
		}
		user.Token = &jwtToken

		resultInsertNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		defer cancel()
		c.JSON(http.StatusOK, resultInsertNumber)
	}
}

// Login function
func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred"})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
		if !passwordIsValid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": msg})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
			return
		}

		// Generate PASETO secret key for login
		pasetoSecret, err := generatePasetoKey()
		if err != nil {
			log.Printf("Error generating PASETO key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate PASETO key"})
			return
		}

		// Generate PASETO token for login
		pasetoClaims := paseto.JSONToken{
			Subject:    *foundUser.User_id,
			Expiration: time.Now().Add(24 * time.Hour),
		}

		pasetoToken, err := paseto.NewV2().Encrypt(pasetoSecret, pasetoClaims, nil)
		if err != nil {
			log.Printf("Error generating PASETO token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate PASETO token"})
			return
		}

		// Update PASETO token in user model (foundUser)
		foundUser.Paseto_token = &pasetoToken

		// Generate JWT secret key for login
		jwtSecret, err := generateJWTKey()
		if err != nil {
			log.Printf("Error generating JWT key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate JWT key"})
			return
		}

		// Generate JWT token for login
		tokenClaimsJWT := jwt.MapClaims{
			"email":      *foundUser.Email,
			"first_name": *foundUser.First_name,
			"last_name":  *foundUser.Last_name,
			"uid":        *foundUser.User_id,
			"user_type":  *foundUser.User_type,
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaimsJWT)
		jwtToken, err := token.SignedString(jwtSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate JWT token"})
			return
		}
		foundUser.Token = &jwtToken

		// Save the updated user model with PASETO token to your database
		// Example: userCollection.UpdateOne(ctx, bson.M{"user_id": foundUser.User_id}, bson.M{"$set": bson.M{"paseto_token": pasetoToken}})

		c.JSON(http.StatusOK, foundUser)
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		helper.CheckUserType(c, "ADMIN")
		err := helper.CheckUserType(c, "ADMIN")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}

		page, err1 := strconv.Atoi(c.Query("page"))
		if err1 != nil || page < 1 {
			page = 1
		}

		startIndex := (page - 1) * recordPerPage
		startIndex, err = strconv.Atoi(c.Query("startIndex"))

		matchStage := bson.D{{"$match", bson.D{{}}}}
		groupStage := bson.D{{"$group", bson.D{{"_id", bson.D{{"_id", "null"}}}, {"total_count", bson.D{{"$sum", 1}}}, {"data", bson.D{{"$push", "$$ROOT"}}}}}}
		projectStage := bson.D{
			{
				"project", bson.D{
					{"_id", 0},
					{"total_count", 1},
					{"users", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage}}}},
				},
			},
		}
		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{matchStage, groupStage, projectStage})
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var allUsers []bson.M
		if err = result.All(ctx, &allUsers); err != nil {
			log.Fatal(err)
		}

		c.JSON(http.StatusOK, allUsers[0])
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("id")

		if err := helper.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, user)
	}
}
