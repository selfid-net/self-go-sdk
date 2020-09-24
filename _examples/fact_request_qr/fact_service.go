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
	"github.com/joinself/self-go-sdk/fact"
)

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
		log.Fatal(err)
	}

	s := server{
		cid:  uuid.New().String(),
		fact: client.FactService(),
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
	client.FactService().Subscribe(func(sender string, resp *fact.QRFactResponse) {
		for _, f := range resp.Facts {
			log.Println(f.Fact, ":", f.AttestedValues())
		}
	})

	WaitForCtrlC()
}

type server struct {
	cid  string
	fact *fact.Service
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
	req := fact.QRFactRequest{
		ConversationID: s.cid,  // this is required. session ID maybe more sensible?
		Description:    "Info", // this is optional
		Facts: []fact.Fact{
			{
				Fact:    fact.FactEmail,                     // required
				Sources: []string{fact.SourceUserSpecified}, // required
			},
		},
		Expiry: time.Minute * 5, // this is required ?
		QRConfig: fact.QRConfig{
			Size:            400,       // this is optional/defaulted
			BackgroundColor: "#FFFFFF", // this is optional/defaulted
			ForegroundColor: "#000000", // this is optional/defaulted
		},
	}

	qrdata, _ := s.fact.GenerateQRCode(&req)

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
