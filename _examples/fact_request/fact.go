package main

import (
	"log"
	"os"
	"time"

	"github.com/selfid-net/self-go-sdk"
	"github.com/selfid-net/self-go-sdk/fact"
)

// expects 1 argument - the Self ID you want to authenticate
func main() {
	cfg := selfsdk.Config{
		SelfID:       os.Getenv("SELF_APP_ID"),
		DeviceID:     "1",
		PrivateKey:   os.Getenv("SELF_APP_SECRET"),
		StorageDir:   "/opt/self/crypto",
		StorageKey:   "my-secret-crypto-storage-key",
		APIURL:       "https://api.review.selfid.net",
		MessagingURL: "wss://messaging.review.selfid.net/v1/messaging",
	}

	client, err := selfsdk.New(cfg)
	if err != nil {
		panic(err)
	}

	err = client.MessagingService().PermitConnection("*")
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) < 2 {
		panic("you must specify a self id as an argument")
	}

	log.Println("requesting user information")

	req := fact.FactRequest{
		SelfID:      os.Args[1],
		Description: "info",
		Facts: []fact.Fact{
			{
				Fact:    fact.FactPhone,
				Sources: []string{fact.SourceUserSpecified},
			},
		},
		Expiry: time.Minute * 5,
	}

	factService := client.FactService()

	resp, err := factService.Request(&req)
	if err != nil {
		log.Fatal("fact request returned with: ", err)
	}

	for _, f := range resp.Facts {
		log.Println(f.Fact, ":", f.AttestedValues())
	}
}
