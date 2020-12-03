// Copyright 2020 Self Group Ltd. All Rights Reserved.

package main

import (
	"fmt"
	"log"
	"os"

	selfsdk "github.com/joinself/self-go-sdk"
	"github.com/joinself/self-go-sdk/messaging"
)

// expects 1 argument - the Self ID you want to permit
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

	fmt.Println("CONNECTIONS EXAMPLE")
	ms := client.MessagingService()

	err = listConnections(ms)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Block all connections")
	err = ms.RevokeConnection("*")
	if err != nil {
		log.Fatal("revoke connection returned with: ", err)
	}
	err = listConnections(ms)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Permit connections from a specific ID")
	err = ms.PermitConnection(os.Args[1])
	if err != nil {
		log.Fatal("permitting connection returned with: ", err)
	}
	err = listConnections(ms)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Permit all connections (replaces all other entries with a wildcard entry)")
	err = ms.PermitConnection("*")
	if err != nil {
		log.Fatal("permitting connection returned with: ", err)
	}
	err = listConnections(ms)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Permit connection from a specific ID (no change as the list already contains a wildcard entry)")
	err = ms.PermitConnection(os.Args[1])
	if err != nil {
		log.Fatal("permitting connection returned with: ", err)
	}
	err = listConnections(ms)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("acl commands succeeded")
}

func listConnections(ms *messaging.Service) error {
	log.Println("List existing connections")
	connections, err := ms.ListConnections()
	if err != nil {
		return err
	}
	log.Println(" - connections : ", connections)
	return nil
}
