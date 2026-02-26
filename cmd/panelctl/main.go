package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"vpspanel/internal/panel/httpapi"

	"database/sql"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "enroll-token":
		enrollToken(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  panelctl enroll-token --db $VPSPANEL_DATABASE_URL --ttl 30m")
}

func enrollToken(args []string) {
	fs := flag.NewFlagSet("enroll-token", flag.ExitOnError)
	dbURL := fs.String("db", os.Getenv("VPSPANEL_DATABASE_URL"), "Postgres connection string")
	ttl := fs.Duration("ttl", 30*time.Minute, "Token TTL")
	fs.Parse(args)

	if *dbURL == "" {
		log.Fatal("--db or VPSPANEL_DATABASE_URL is required")
	}

	db, err := sql.Open("pgx", *dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tok, err := httpapi.NewEnrollmentToken(ctx, db, *ttl)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(tok)
}
