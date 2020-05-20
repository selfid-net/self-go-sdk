package main

import (
	"log"
	"os"

	selfsdk "github.com/selfid-net/self-go-sdk"
)

// expects 1 argument - the Self ID you want to permit
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

	if len(os.Args) < 2 {
		panic("you must specify a self id as an argument")
	}

	log.Println("blocking user")

	ms := client.MessagingService()

	// revoke a connection
	err = ms.RevokeConnection(os.Args[1])
	if err != nil {
		log.Fatal("acl command returned with: ", err)
	}

	// permit a connection
	err = ms.PermitConnection(os.Args[1])
	if err != nil {
		log.Fatal("acl command returned with: ", err)
	}

	// list all connections
	connections, err := ms.ListConnections()
	if err != nil {
		log.Fatal("acl command returned with: ", err)
	}

	log.Println("connected to:", connections)

	log.Println("acl commands succeeded")
}
