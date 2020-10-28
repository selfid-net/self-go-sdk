package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	selfsdk "github.com/joinself/self-go-sdk"
	"github.com/joinself/self-go-sdk/authentication"
)

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

	client.AuthenticationService().Subscribe(func(sender, cid string, authenticated bool) {
		log.Println("cid: " + cid)
		if authenticated {
			log.Println("authentication accepted by " + sender)
		} else {
			log.Println("authentication rejected by " + sender)
		}
	})
	WaitForCtrlC()
}

type server struct {
	cid  string
	auth *authentication.Service
}

func WaitForCtrlC() {
	var end_waiter sync.WaitGroup
	end_waiter.Add(1)
	var signal_channel chan os.Signal
	signal_channel = make(chan os.Signal, 1)
	signal.Notify(signal_channel, os.Interrupt)
	go func() {
		<-signal_channel
		end_waiter.Done()
	}()
	end_waiter.Wait()
}

// serves the qr code image
func (s server) qrcode(w http.ResponseWriter, r *http.Request) {
	req := authentication.QRAuthenticationRequest{
		ConversationID: "jkhagsdfkjhasgdkfjhasg",
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
