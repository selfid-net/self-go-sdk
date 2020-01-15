package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	selfsdk "github.com/selfid-net/self-go-sdk"
)

var upgrader = websocket.Upgrader{}

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
		cid := uuid.New().String()
		http.SetCookie(w, &http.Cookie{Name: "self", Value: cid})

		http.ServeFile(w, r, "./html/index.html")
	}
}

// what is cid (cookie.Value)?
// what is fields?
// default size
// default expiry
// make fields optional
func (s *server) handleQRcode() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("self")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		fields := make(map[string]interface{})

		qr, err := s.self.GenerateQRCode("authentication_req", cookie.Value, fields, 400, time.Minute*5)
		//qr, err := self.GenerateQRCode("authentication_req", cookie.Value, fields, 400, time.Minute*5)
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

func (s *server) handleAuth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			http.Error(w, err.Error(), 500)
		}
		defer ws.Close()

		cookie, err := r.Cookie("self")
		if err != nil {
			ws.WriteJSON(map[string]string{"status": "rejected"})
			return
		}

		resp, err := s.self.WaitForResponse(cookie.Value, time.Minute)
		if err != nil {
			ws.WriteJSON(map[string]string{"status": "rejected"})
			return
		}

		err = s.self.ValidateAuth(resp.Ciphertext)
		if err != nil {
			ws.WriteJSON(map[string]string{"status": "rejected"})
			return
		}

		ws.WriteJSON(map[string]string{"status": "accepted"})
	}
}

func (s *server) routes() {
	s.router = chi.NewRouter()
	s.router.Get("/", s.handleIndex())
	s.router.Get("/qrcode", s.handleQRcode())
	s.router.Get("/auth", s.handleAuth())
}
