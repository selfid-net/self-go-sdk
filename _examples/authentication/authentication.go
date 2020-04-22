package main

import (
	"log"
	"os"

	"github.com/selfid-net/self-go-sdk"
)

// expects 1 argument - the Self ID you want to authenticate
func main() {
	cfg := selfsdk.Config{
		SelfID:     os.Getenv("SELF_APP_ID"),
		DeviceID:   "1",
		PrivateKey: os.Getenv("SELF_APP_SECRET"),
		StorageDir: "/opt/self/crypto",
		StorageKey: "my-secret-crypto-storage-key",
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
