package main

import (
	"fmt"
	"net/http"
	"os"

	selfsdk "github.com/selfid-net/self-go-sdk"
)

func main() {
	appID := os.Getenv("APP_ID")
	appKey := os.Getenv("APP_KEY")

	self, err := selfsdk.New(appID, appKey)
	if err != nil {
		fmt.Println(err)
	}

	err = self.PermitConnection("*")
	if err != nil {
		fmt.Println(err)
	}

	srv := newServer()
	srv.self = self

	fmt.Println("server listening on :4000")
	fmt.Println(http.ListenAndServe(":4000", srv))
}
