package config

import (
	"os"
)

var (
	AccessSecret  = ""
	RedisAddr     = ""
	GinPort       = ""
	GinMode       = ""
	RefreshSecret = ""
)

// GetEnvDefault is responsible for getting environment variable
// if it fails to get then it will return provided default value
func GetEnvDefault(key, defVal string) string {
	val, ex := os.LookupEnv(key)
	if !ex {
		return defVal
	}
	return val
}

// SetEnvironment is responsible for getting environment variable from os environment and setting in local variables
func SetEnvironment() {
	AccessSecret = os.Getenv("ACCESS_SECRET")
	RedisAddr = os.Getenv("REDIS_DB")
	GinPort = GetEnvDefault("GIN_PORT", "8008")
	GinMode = os.Getenv("GIN_MODE")
	RefreshSecret = os.Getenv("REFRESH_SECRET")
}
