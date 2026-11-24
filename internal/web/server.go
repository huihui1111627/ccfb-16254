// Package web serves the local simulation dashboard and JSON API.
package web

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"sync"
	"time"

	"cidlb/internal/sim"
)

//go:embed static
var staticFS embed.FS

type Server struct {
	mu     sync.RWMutex
	cfg    sim.Config
	result *sim.Result
	ranAt  time.Time
}

func New(cfg sim.Config) (*Server, error) {
	r, err := sim.Run(cfg)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, result: r, ranAt: time.Now()}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/packets", s.handlePackets)
	mux.HandleFunc("/api/rerun", s.handleRerun)
	mux.Handle("/", http.FileServer(http.FS(mustSub(staticFS, "static"))))
	return mux
}

func mustSub(staticFS embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(staticFS, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, map[string]any{
		"report": s.result.Report,
		"ranAt":  s.ranAt,
	})
}

func (s *Server) handlePackets(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	trace := r.URL.Query().Get("trace")
	if trace == "" {
		http.Error(w, "missing trace", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	packets := s.result.Packets(mode, trace)
	s.mu.RUnlock()
	writeJSON(w, map[string]any{"mode": mode, "trace": trace, "packets": packets})
}

func (s *Server) handleRerun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := s.cfg
	if v := r.URL.Query().Get("users"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 300 {
			cfg.Users = n
		}
	}
	if v := r.URL.Query().Get("seed"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.Seed = n
		}
	}
	if v := r.URL.Query().Get("durationSec"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 20 && n <= 900 {
			cfg.DurationMS = n * 1000
		}
	}
	result, err := sim.Run(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	s.cfg = cfg
	s.result = result
	s.ranAt = time.Now()
	s.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
