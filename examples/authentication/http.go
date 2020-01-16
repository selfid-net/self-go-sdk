package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	selfsdk "github.com/selfid-net/self-go-sdk"
)

type server struct {
	router *chi.Mux
	self   *selfsdk.Client
}

func newServer() *server {
	s := &server{}
	s.routes()
	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *server) handleIndex() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create and store a unique session identifier.
		cid := uuid.New().String()
		http.SetCookie(w, &http.Cookie{Name: "self", Value: cid})

		http.ServeFile(w, r, "./html/index.html")
	}
}

// Endpoint to generate QR code.
func (s *server) handleQRcode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Fetch session identifier.
		cookie, err := r.Cookie("self")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		fields := make(map[string]interface{})

		// Generate QR code.
		//qr, err := s.self.GenerateQRCode(selfsdk.TypeAuthenticationRequest, cookie.Value, 400)
		qr, err := s.self.GenerateQRCode(selfsdk.TypeAuthenticationRequest, cookie.Value, fields, 400, time.Minute*5)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		_, err = w.Write(qr)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
}

// Endpoint for browser to app communication.
// This can be handled in various ways. For this example we will be using
// websockets.
func (s *server) handleAuth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		wsconn := websocket.Upgrader{}

		ws, err := wsconn.Upgrade(w, r, nil)
		if err != nil {
			http.Error(w, err.Error(), 500)
		}
		defer ws.Close()

		cookie, err := r.Cookie("self")
		if err != nil {
			fmt.Println(err)
			ws.WriteJSON(map[string]string{"status": "rejected"})
			return
		}

		// Wait for the authentication response.
		resp, err := s.self.WaitForResponse(cookie.Value, time.Minute)
		if err != nil {
			fmt.Println(err)
			ws.WriteJSON(map[string]string{"status": "rejected"})
			return
		}

		// Validate the authentication response.
		err = s.self.ValidateAuth(resp.Ciphertext)
		if err != nil {
			fmt.Println(err)
			ws.WriteJSON(map[string]string{"status": "rejected"})
			return
		}

		ws.WriteJSON(map[string]string{"status": "accepted"})
	}
}

func (s *server) handleAccept() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./html/accept.html")
	}
}

func (s *server) handleReject() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./html/reject.html")
	}
}

func (s *server) routes() {
	s.router = chi.NewRouter()
	s.router.Get("/", s.handleIndex())
	s.router.Get("/qrcode", s.handleQRcode())
	s.router.Get("/auth", s.handleAuth())
	s.router.Get("/accept", s.handleAccept())
	s.router.Get("/reject", s.handleReject())
}
