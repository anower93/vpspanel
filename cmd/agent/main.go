package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vpspanel/internal/agent"
)

func main() {
	cfg, err := agent.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	ag, err := agent.NewAgent(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer ag.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = ag.Shutdown(shutdownCtx)
	}()

	log.Printf("vpspanel agent listening on %s", cfg.ListenAddr)
	if err := ag.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
