package main

import (
	routes "golangjwt-develop/routes"
	// import routes
	"os"

	"github.com/gin-gonic/gin" // import gin
)

func main() {
	port := os.Getenv("PORT") // mengambil port dari env

	if port == "" {
		port = "8080" //localhost
	}
	router := gin.New()      // membuat router baru
	router.Use(gin.Logger()) // menggunakan logger

	routes.AuthRoutes(router) // menggunakan routes auth
	routes.UserRoutes(router) // menggunakan routes user

	router.GET("/api-1", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello World",
		}) // membuat api di passing menjadi berupa json dan memunculkan hello world
	})
	router.GET("/api-2", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello World"}) // membuat api di passing menjadi berupa json dan memunculkan hello world
	})

	router.Run(":" + port) // menjalankan router di port yang diambil dari env (localhost
}
