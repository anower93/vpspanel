package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vpspanel/internal/panel"
)

func main() {
	cfg, err := panel.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	app, err := panel.NewApp(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer app.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = app.Shutdown(shutdownCtx)
	}()

	log.Printf("vpspanel panel listening on %s", cfg.ListenAddr)
	if err := app.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
