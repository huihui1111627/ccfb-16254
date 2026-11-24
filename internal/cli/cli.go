// Package cli wires the command-line flags to the simulation web server.
package cli

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cidlb/internal/sim"
	"cidlb/internal/web"
)

// Main runs the cidlb command.
func Main() {
	addr := flag.String("addr", envOr("ADDR", "127.0.0.1:8080"), "HTTP listen address")
	users := flag.Int("users", 96, "number of simulated phone users")
	duration := flag.Int("duration-sec", 160, "simulated duration in seconds")
	seed := flag.Int64("seed", sim.DefaultConfig().Seed, "deterministic random seed")
	flag.Parse()

	cfg := sim.DefaultConfig()
	cfg.Users = *users
	cfg.DurationMS = *duration * 1000
	cfg.Seed = *seed

	srv, err := web.New(cfg)
	if err != nil {
		log.Fatalf("initialize simulation: %v", err)
	}
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		log.Printf("QUIC CID LB dashboard: http://%s", *addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server: %v", err)
		}
	}()
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
