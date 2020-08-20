package main

import (
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	selfsdk "github.com/joinself/self-go-sdk"
	"github.com/joinself/self-go-sdk/authentication"
)

// expects 1 argument - the Self ID you want to authenticate
func main() {
	cfg := selfsdk.Config{
		SelfAppID:     os.Getenv("SELF_APP_ID"),
		SelfAppSecret: os.Getenv("SELF_APP_SECRET"),
		StorageKey:    "my-secret-crypto-storage-key",
	}

	if os.Getenv("SELF_ENV") != "" {
		cfg.Environment = os.Getenv("SELF_ENV")
	}

	client, err := selfsdk.New(cfg)
	if err != nil {
		panic(err)
	}

	log.Println("authenticating user")

	authService := client.AuthenticationService()
	cid := uuid.New().String()

	req := authentication.DeepLinkAuthenticationRequest{
		ConversationID: cid,
		Callback:       "https://www.selfid.net",
		Expiry:         time.Minute * 5,
	}

	link, err := authService.GenerateDeepLink(&req)
	if err != nil {
		log.Fatal("auth returned with: ", err)
	}

	log.Println("Click on " + link)

	err = authService.WaitForResponse(cid, time.Minute)
	if err != nil {
		log.Fatal("auth returned with: ", err)
	}

	log.Println("authentication succeeded")
}
