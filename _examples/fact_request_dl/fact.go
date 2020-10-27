package main

import (
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	selfsdk "github.com/joinself/self-go-sdk"
	"github.com/joinself/self-go-sdk/fact"
)

// expects 1 argument - the Self ID you want to authenticate
func main() {
	cid := uuid.New().String()

	cfg := selfsdk.Config{
		SelfAppID:     os.Getenv("SELF_APP_ID"),
		SelfAppSecret: os.Getenv("SELF_APP_SECRET"),
		StorageKey:    "my-secret-crypto-storage-key",
		StorageDir:    "../.storage",
	}

	if os.Getenv("SELF_ENV") != "" {
		cfg.Environment = os.Getenv("SELF_ENV")
	}

	client, err := selfsdk.New(cfg)
	if err != nil {
		panic(err)
	}

	err = client.MessagingService().PermitConnection("*")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("requesting user information")

	req := fact.DeepLinkFactRequest{
		ConversationID: cid,
		Description:    "info",
		Callback:       "https://www.joinself.com",
		Facts: []fact.Fact{
			{
				Fact:    fact.FactPhone,
				Sources: []string{fact.SourceUserSpecified},
			},
		},
		Expiry: time.Minute * 5,
	}

	factService := client.FactService()

	link, err := factService.GenerateDeepLink(&req)
	if err != nil {
		log.Fatal("fact request returned with: ", err)
	}

	log.Println("Click on " + link)

	resp, err := factService.WaitForResponse(cid, time.Minute)
	if err != nil {
		log.Fatal("fact request returned with: ", err)
	}

	for _, f := range resp.Facts {
		log.Println(f.Fact, ":", f.AttestedValues())
	}
}
