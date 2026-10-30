package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Device struct {
	ID             string    `json:"id"`
	Model          string    `json:"model"`
	OSVersion      string    `json:"osVersion"`
	AppVersion     string    `json:"appVersion"`
	BatteryPercent int       `json:"batteryPercent"`
	LastSeen       time.Time `json:"lastSeen"`
}

type enrollRequest struct {
	Model      string `json:"model"`
	OSVersion  string `json:"osVersion"`
	AppVersion string `json:"appVersion"`
}

type heartbeatRequest struct {
	AppVersion     string `json:"appVersion"`
	OSVersion      string `json:"osVersion"`
	BatteryPercent int    `json:"batteryPercent"`
}

type Server struct {
	mu          sync.RWMutex
	devices     map[string]Device
	credentials map[string]string
	adminToken  string
}

func newServer(adminToken string) *Server {
	return &Server{devices: make(map[string]Device), credentials: make(map[string]string), adminToken: adminToken}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.HandleFunc("POST /v1/heartbeat", s.heartbeat)
	mux.HandleFunc("GET /v1/devices", s.admin(s.listDevices))
	mux.HandleFunc("DELETE /v1/devices/{id}", s.admin(s.revokeDevice))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !bearerMatches(r, s.adminToken) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var input enrollRequest
	if decodeJSON(w, r, &input) != nil || !validText(input.Model, 100) || !validText(input.OSVersion, 50) || !validText(input.AppVersion, 50) {
		http.Error(w, "invalid enrollment payload", http.StatusBadRequest)
		return
	}
	id, err := randomHex(16)
	if err != nil {
		http.Error(w, "enrollment unavailable", http.StatusInternalServerError)
		return
	}
	credential, err := randomHex(32)
	if err != nil {
		http.Error(w, "enrollment unavailable", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	device := Device{ID: id, Model: input.Model, OSVersion: input.OSVersion, AppVersion: input.AppVersion, BatteryPercent: -1, LastSeen: now}
	s.mu.Lock()
	s.devices[id] = device
	s.credentials[id] = hashCredential(credential)
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"device": device, "deviceToken": credential})
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	var input heartbeatRequest
	if decodeJSON(w, r, &input) != nil || !validText(input.AppVersion, 50) || !validText(input.OSVersion, 50) || input.BatteryPercent < 0 || input.BatteryPercent > 100 {
		http.Error(w, "invalid heartbeat payload", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.Header.Get("X-Device-ID"))
	token := bearerToken(r)
	s.mu.Lock()
	expected, exists := s.credentials[id]
	if !exists || !credentialMatches(token, expected) {
		s.mu.Unlock()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	device := s.devices[id]
	device.AppVersion = input.AppVersion
	device.OSVersion = input.OSVersion
	device.BatteryPercent = input.BatteryPercent
	device.LastSeen = time.Now().UTC()
	s.devices[id] = device
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listDevices(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	devices := make([]Device, 0, len(s.devices))
	for _, device := range s.devices {
		devices = append(devices, device)
	}
	s.mu.RUnlock()
	sort.Slice(devices, func(i, j int) bool { return devices[i].ID < devices[j].ID })
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	_, exists := s.devices[id]
	delete(s.devices, id)
	delete(s.credentials, id)
	s.mu.Unlock()
	if !exists {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func validText(value string, max int) bool {
	return len(strings.TrimSpace(value)) > 0 && len(value) <= max
}

func randomHex(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func hashCredential(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func credentialMatches(value, expectedHash string) bool {
	if value == "" || expectedHash == "" {
		return false
	}
	actual := hashCredential(value)
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expectedHash)) == 1
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func bearerMatches(r *http.Request, expected string) bool {
	provided := bearerToken(r)
	if provided == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func main() {
	adminToken := os.Getenv("ADMIN_TOKEN")
	if len(adminToken) < 32 {
		log.Fatal("ADMIN_TOKEN must be set to at least 32 characters")
	}
	address := os.Getenv("LISTEN_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	server := &http.Server{Addr: address, Handler: newServer(adminToken).routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	log.Printf("consent monitor listening on %s; terminate with SIGINT/SIGTERM", address)
	log.Fatal(server.ListenAndServe())
}