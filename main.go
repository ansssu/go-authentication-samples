package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

var tokens []string

func main() {
	r := gin.Default()

	r.POST("/login", gin.BasicAuth(gin.Accounts{
		"admin": "secret",
	}), func(c *gin.Context) {
		token, _ := randomHex(20)
		tokens = append(tokens, token)
		c.JSON(http.StatusOK, gin.H{
			"token": token,
		})
	})

	r.GET("/resource", func(c *gin.Context) {
		bearerToken := c.Request.Header.Get("Authorization")
		reqToken := strings.Split(bearerToken, " ")[1]
		for _, token := range tokens {
			if token == reqToken {
				c.JSON(http.StatusOK, gin.H{
					"data": "resource data",
				})
			}
		}
	})
	r.Run()
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
