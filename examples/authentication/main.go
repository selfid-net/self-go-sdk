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

	//self, _ := selfsdk.New(appID, appKey)
	self, err := selfsdk.New(appID, appKey, selfsdk.SetEndpoint("http://10.49.15.22:8080"), selfsdk.SetMessagingEndpoint("ws://10.49.15.22:8086/v1/messaging"))
	if err != nil {
		fmt.Println(err)
	}

	err = self.ACLAllow("*")
	if err != nil {
		fmt.Println(err)
	}

	srv := newServer()
	srv.self = self

	fmt.Println("server listening on :4000")
	fmt.Println(http.ListenAndServe(":4000", srv))
}
