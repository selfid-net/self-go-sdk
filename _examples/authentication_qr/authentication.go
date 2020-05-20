package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/google/uuid"
	selfsdk "github.com/selfid-net/self-go-sdk"
	"github.com/selfid-net/self-go-sdk/authentication"
)

func main() {
	cfg := selfsdk.Config{
		SelfAppID:     os.Getenv("SELF_ID"),
		SelfAppSecret: os.Getenv("SELF_KEY"),
		StorageKey:    "my-secret-crypto-storage-key",
	}

	client, err := selfsdk.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	s := server{
		cid:  uuid.New().String(),
		auth: client.AuthenticationService(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/qr.png", s.qrcode)

	log.Println("starting server")

	l, err := net.Listen("tcp", ":9999")
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		err := http.Serve(l, mux)
		if err != nil {
			log.Fatal(err)
		}
	}()

	openbrowser("http://localhost:9999/qr.png")

	log.Println("waiting for response")

	err = s.auth.WaitForResponse(s.cid, time.Minute)
	if err != nil {
		log.Fatal("auth returned with: ", err)
	}

	log.Println("authentication succeeded")
}

type server struct {
	cid  string
	auth *authentication.Service
}

// serves the qr code image
func (s server) qrcode(w http.ResponseWriter, r *http.Request) {
	req := authentication.QRAuthenticationRequest{
		ConversationID: s.cid,
		Expiry:         time.Minute * 5,
		QRConfig: authentication.QRConfig{
			Size:            400,
			BackgroundColor: "#FFFFFF",
			ForegroundColor: "#000000",
		},
	}

	qrdata, err := s.auth.GenerateQRCode(&req)
	if err != nil {
		log.Fatal(err)
	}

	w.Write(qrdata)
}

// ignore this stuff
func openbrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		log.Fatal("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}
}
