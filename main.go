package main

import (
	"fmt"
	"github.com/HelpDeskPlatform/gin-jwt/config"
	"github.com/HelpDeskPlatform/gin-jwt/db"
	"github.com/HelpDeskPlatform/gin-jwt/jwt"
	"github.com/gin-gonic/gin"
	"github.com/x1unix/godotenv"
	"log"
)

func initEnv() {
	log.Printf("Loading environment settings.")
	if err := godotenv.Load("../../.env"); err != nil {
		log.Println("No local env file. Using global OS environment variables")
	}
	config.SetEnvironment()
	if err := db.NewDatabase(config.RedisAddr); err != nil {
		log.Println(err)
	}
}

func init() {
	initEnv()
}

func main() {
	if config.GinMode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}
	token := jwt.Token{ID: "hello"}
	jwtToken := token.Login()
	id, err := jwt.Authorize("Bearer " + jwtToken.AccessToken)
	if err != nil {
		panic(err)
	}
	fmt.Println("Id is: ", id)
}
