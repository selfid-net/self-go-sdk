package main

import (
	"encoding/json"
	"os"
	"runtime"
	"time"

	"github.com/google/uuid"
	selfsdk "github.com/selfid-net/self-go-sdk"
	"github.com/selfid-net/self-go-sdk/fact"
	"github.com/selfid-net/self-go-sdk/messaging"
	"github.com/selfid-net/self-go-sdk/pkg/ntp"
)

func main() {
	cfg := selfsdk.Config{
		SelfAppID:     os.Getenv("SELF_APP_ID"),
		SelfAppSecret: os.Getenv("SELF_APP_SECRET"),
		StorageDir:    "/opt/self/crypto",
		StorageKey:    "my-secret-crypto-storage-key",
	}

	client, err := selfsdk.New(cfg)
	if err != nil {
		panic(err)
	}

	ms := client.MessagingService()
	fs := client.FactService()

	s := server{
		messaging: ms,
		fact:      fs,
	}

	ms.Subscribe("document_verification_req", s.verification)

	runtime.Goexit()
}

type server struct {
	messaging *messaging.Service
	fact      *fact.Service
}

type verificationRequest struct {
	ConversationID     string `json:"cid"`
	Issuer             string `json:"iss"`
	DocumentType       string `json:"document_type"`
	DocumentImageFront string `json:"document_image_front"`
	DocumentImageBack  string `json:"document_image_back"`
	SelfieImage        string `json:"selfie_image"`
}

type verificationResponse struct {
	ConversationID string            `json:"cid"`
	MessageType    string            `json:"typ"`
	Nonce          string            `json:"jti"`
	Issuer         string            `json:"iss"`
	Recipient      string            `json:"aud"`
	Subject        string            `json:"sub"`
	Issued         time.Time         `json:"iat"`
	Expires        time.Time         `json:"exp"`
	Status         string            `json:"status"`
	Attestations   []json.RawMessage `json:"attestations"`
}

func (s server) verification(m *messaging.Message) {
	var req verificationRequest

	err := json.Unmarshal(m.Payload, &req)
	if err != nil {
		panic(err) // proper error handling needed here...
	}

	if req.DocumentType != fact.SourcePassport {
		panic(err) // proper error handling needed here...
	}

	// do something with document images

	facts := []fact.Fact{
		{
			Fact:          "given_names",
			AttestedValue: "party",
		},
		{
			Fact:          "surname",
			AttestedValue: "parrot",
		},
	}

	attestations, err := s.fact.Attest(m.Sender, facts)
	if err != nil {
		panic(err) // proper error handling needed here...
	}

	resp, err := json.Marshal(verificationResponse{
		ConversationID: req.ConversationID,
		Nonce:          uuid.New().String(),
		MessageType:    "document_verification_resp",
		Issuer:         os.Getenv("SELF_ID"),
		Recipient:      req.Issuer,
		Subject:        req.Issuer,
		Issued:         ntp.TimeFunc(),
		Expires:        ntp.TimeFunc().Add(time.Hour),
		Status:         fact.StatusAccepted,
		Attestations:   attestations,
	})

	if err != nil {
		panic(err) // proper error handling needed here...
	}

	err = s.messaging.Respond(m.Sender, req.ConversationID, resp)
	if err != nil {
		panic(err) // proper error handling needed here...
	}
}
