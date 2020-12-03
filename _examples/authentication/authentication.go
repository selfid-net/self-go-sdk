// Copyright 2020 Self Group Ltd. All Rights Reserved.

package main

import (
	"log"
	"os"

	selfsdk "github.com/joinself/self-go-sdk"
)

// expects 1 argument - the Self ID you want to authenticate
func main() {
	cfg := selfsdk.Config{
		SelfAppID:     os.Getenv("SELF_APP_ID"),
		SelfAppSecret: os.Getenv("SELF_APP_SECRET"),
		StorageKey:    "my-secret-crypto-storage-key",
		StorageDir:    "../.storage/" + os.Getenv("SELF_APP_ID"),
	}

	if os.Getenv("SELF_ENV") != "" {
		cfg.Environment = os.Getenv("SELF_ENV")
	}

	client, err := selfsdk.New(cfg)
	if err != nil {
		panic(err)
	}

	if len(os.Args) < 2 {
		panic("you must specify a self id as an argument")
	}

	log.Println("authenticating user")

	authService := client.AuthenticationService()

	err = authService.Request(os.Args[1])
	if err != nil {
		log.Fatal("auth returned with: ", err)
	}

	log.Println("authentication succeeded")
}
