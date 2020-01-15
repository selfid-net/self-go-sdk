package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	selfsdk "github.com/selfid-net/self-go-sdk"
	msgproto "github.com/selfid-net/self-messaging-proto"
	"github.com/square/go-jose"
)

func main() {
	// Self SDK
	// default value for auto reconnect
	//
	// appID := os.Getenv("APP_ID"),
	// appKey := os.Getenv("APP_KEY"),
	// self, _ := selfsdk.New(appID, appKey)
	self, err := selfsdk.New(
		os.Getenv("APP_ID"),
		os.Getenv("APP_KEY"),
		selfsdk.SetEndpoint("http://10.49.15.22:8080"),
		selfsdk.SetMessagingEndpoint("ws://10.49.15.22:8086/v1/messaging"),
		selfsdk.SetMessagingDevice("10"),
		selfsdk.AutoReconnect(true),
	)
	if err != nil {
		fmt.Println(err)
	}

	err = self.ACLAllow("*")
	if err != nil {
		fmt.Println(err)
	}

	self.OnMessage("authentication_resp", func(m *msgproto.Message) {
		jws, err := jose.ParseSigned(string(m.Ciphertext))
		if err != nil {
			fmt.Println(err)
			return
		}

		var resp map[string]interface{}

		err = json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &resp)
		if err != nil {
			fmt.Println(err)
			return
		}

		// srv.events.notify(resp["cid"].(string), nil) ???
	})

	srv := newServer()
	srv.self = self

	fmt.Println("server listening on :4000")
	fmt.Println(http.ListenAndServe(":4000", srv))
}
