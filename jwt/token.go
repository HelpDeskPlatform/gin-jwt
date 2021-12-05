package jwt

import (
	"fmt"
	"github.com/HelpDeskPlatform/gin-jwt/config"
	"github.com/HelpDeskPlatform/gin-jwt/db"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"strings"
	"time"
)

type Token struct {
	ID string
}

type tokenDetails struct {
	accessToken  string
	refreshToken string
	accessUuid   string
	refreshUuid  string
	atExpires    int64
	rtExpires    int64
}

type accessDetails struct {
	accessUuid string
	userId     string
}

type authToken struct {
	AccessToken  string
	RefreshToken string
}

func (t Token) createToken() (*tokenDetails, error) {
	td := &tokenDetails{}
	td.atExpires = time.Now().Add(time.Minute * 15).Unix()
	td.accessUuid = uuid.New().String()

	td.rtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.refreshUuid = uuid.New().String()

	var err error
	atClaims := jwt.MapClaims{
		"authorized":  true,
		"user_id":     t.ID,
		"access_uuid": td.accessUuid,
		"exp":         time.Now().Add(time.Minute * 15).Unix(),
	}
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.accessToken, err = at.SignedString([]byte(config.AccessSecret))
	if err != nil {
		return nil, err
	}
	rtClaims := jwt.MapClaims{
		"refresh_uuid": td.refreshUuid,
		"user_id":      t.ID,
		"exp":          td.rtExpires,
	}
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.refreshToken, err = rt.SignedString([]byte(config.RefreshSecret))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func (t Token) createAuth(td *tokenDetails) error {
	at := time.Unix(td.atExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(td.rtExpires, 0)
	now := time.Now()
	client := db.GetRedisDb()
	errAccess := client.SetKey(td.accessUuid, t.ID, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	cmdRefresh := client.SetKey(td.refreshUuid, t.ID, rt.Sub(now))
	return cmdRefresh.Err()
}

func extractToken(bearToken string) string {
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func parseToken(tokenString string, secret string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
}

func verifyToken(bearToken string) (*jwt.Token, error) {
	tokenString := extractToken(bearToken)
	token, err := parseToken(tokenString, config.AccessSecret)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func extractTokenMetadata(bearToken string) (*accessDetails, error) {
	token, err := verifyToken(bearToken)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userId := claims["user_id"].(string)
		return &accessDetails{
			accessUuid: accessUuid,
			userId:     userId,
		}, nil
	}
	return nil, err
}

func fetchAuth(authD *accessDetails) (string, error) {
	client := db.GetRedisDb()
	userid, err := client.GetByKey(authD.accessUuid)
	if err != nil {
		return "", err
	}
	return userid, nil
}

func deleteAuth(givenUuid string) (int64, error) {
	deleted, err := db.GetRedisDb().DelById(givenUuid)
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// Authorize for authorizing every request
func Authorize(token string) (string, error) {
	accessDetails, err := extractTokenMetadata(token)
	if err != nil {
		return "", err
	}
	return fetchAuth(accessDetails)
}

// Login generate access token and logged
func (t Token) Login() authToken {
	token, err := t.createToken()
	if err != nil {
		panic(err)
	}
	if err := t.createAuth(token); err != nil {
		panic(err)
	}
	return authToken{AccessToken: token.accessToken, RefreshToken: token.refreshToken}
}

// Logout user while decided to logged out from his own
func Logout(token string) error {
	au, err := extractTokenMetadata(token)
	if err != nil {
		return err
	}
	deleted, delErr := deleteAuth(au.accessUuid)
	if delErr != nil || deleted == 0 {
		return delErr
	}
	return nil
}

// TokenRefresh for refresh token after access token invalided
func TokenRefresh(refreshToken string) (*authToken, error) {
	token, err := parseToken(refreshToken, config.RefreshSecret)
	if err != nil {
		return nil, err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string)
		if !ok {
			return nil, fmt.Errorf("something went wrong while getting refresh uid")
		}
		userId := claims["user_id"].(string)
		deleted, delErr := deleteAuth(refreshUuid)
		if delErr != nil || deleted == 0 {
			return nil, delErr
		}
		t := Token{ID: userId}
		authToken := t.Login()
		return &authToken, nil

	} else {
		return nil, fmt.Errorf("refresh expired")
	}
}
