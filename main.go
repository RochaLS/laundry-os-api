package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type Command struct {
	DeviceID        string `json:"deviceId"`
	Type            string `json:"type"` // wash | dry
	DurationMinutes int    `json:"durationMinutes"`
	CreatedAt       int64  `json:"createdAt"`
	Token           string `json:"token,omitempty"` // only in request
}

type LatestResponse struct {
	Command *Command `json:"command"`
}

var sharedSecret = os.Getenv("SHARED_SECRET")

var (
	mu             sync.Mutex
	latestByDevice = map[string]Command{}
	lastServedAt   = map[string]int64{}
)

func timingSafeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*") // fine for v1
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func startMachine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method not allowed")
		return
	}

	var cmd Command
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		writeErr(w, 400, "invalid json")
		return
	}

	if cmd.Token == "" || !timingSafeEq(cmd.Token, sharedSecret) {
		writeErr(w, 401, "unauthorized")
		return
	}

	if cmd.DeviceID == "" {
		writeErr(w, 400, "deviceId required")
		return
	}

	if cmd.Type != "wash" && cmd.Type != "dry" {
		writeErr(w, 400, "type must be wash or dry")
		return
	}

	if cmd.DurationMinutes <= 0 {
		writeErr(w, 400, "duration must be greater than 0 minutes")
		return
	}

	cmd.CreatedAt = time.Now().UnixMilli()
	cmd.Token = "" // don’t keep token

	mu.Lock()
	latestByDevice[cmd.DeviceID] = cmd
	mu.Unlock()

	writeJSON(w, 200, map[string]any{"ok": true, "createdAt": cmd.CreatedAt})
}

func getLatest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method not allowed")
		return
	}

	deviceID := r.URL.Query().Get("deviceId")
	token := r.URL.Query().Get("token")

	if deviceID == "" {
		writeErr(w, 400, "deviceId required")
		return
	}

	if token == "" || !timingSafeEq(token, sharedSecret) {
		writeErr(w, 401, "unauthorized")
		return
	}

	mu.Lock()
	defer mu.Unlock()

	cmd, ok := latestByDevice[deviceID]
	if !ok {
		writeJSON(w, 200, LatestResponse{Command: nil})
		return
	}

	if lastServedAt[deviceID] >= cmd.CreatedAt {
		writeJSON(w, 200, LatestResponse{Command: nil})
		return
	}

	lastServedAt[deviceID] = cmd.CreatedAt
	writeJSON(w, 200, LatestResponse{Command: &cmd})
}

func main() {
	http.HandleFunc("/start", startMachine)
	http.HandleFunc("/command/latest", getLatest)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081" // local fallback
	}

	log.Println("Laundry OS API listening on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
