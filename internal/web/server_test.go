package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cidlb/internal/sim"
)

func TestDashboardAPIAndEmbeddedAssets(t *testing.T) {
	cfg := sim.DefaultConfig()
	cfg.Users = 16
	cfg.DurationMS = 45_000
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("state status = %d", rec.Code)
	}
	var state struct {
		Report struct {
			Migrations []any `json:"migrations"`
		} `json:"report"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/", "/app.js", "/styles.css"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, rec.Code)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/api/packets?mode=cid&trace=missing", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("packets status = %d", rec.Code)
	}
}
