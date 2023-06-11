package routes

import (
	controller "golangjwt-develop/controllers"
	"golangjwt-develop/middleware"

	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) { // membuat routes auth
	incomingRoutes.Use(middleware.Authenticate())      // menggunakan middleware authenticate
	incomingRoutes.GET("/user", controller.GetUsers()) // membuat routes user untuk mengani user
	incomingRoutes.GET("/user/:user_id", controller.GetUser())
}
