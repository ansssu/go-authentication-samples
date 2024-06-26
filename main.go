package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/resource", gin.BasicAuth(gin.Accounts{
		"admin": "secret",
	}), func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"data": "resource data",
		})
	})
	r.Run()
}
