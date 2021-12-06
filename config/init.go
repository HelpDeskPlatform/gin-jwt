package config

import (
	"github.com/HelpDeskPlatform/gin-jwt/db"
	"log"
)

func InIt() {
	SetEnvironment()
	if err := db.NewDatabase(RedisAddr); err != nil {
		log.Println(err)
	}
}
