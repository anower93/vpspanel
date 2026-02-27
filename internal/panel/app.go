package panel

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"vpspanel/internal/panel/ca"
	"vpspanel/internal/panel/db"
	"vpspanel/internal/panel/httpapi"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type App struct {
	cfg    *Config
	db     *sql.DB
	ca     *ca.CA
	server *http.Server
}

func NewApp(cfg *Config) (*App, error) {
	if err := os.MkdirAll(cfg.DataDir, 0750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	sqlDB, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("db open: %w", err)
	}
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("db ping: %w", err)
	}
	if err := db.Migrate(ctx, sqlDB); err != nil {
		return nil, err
	}

	caDir := filepath.Join(cfg.DataDir, "ca")
	panelCA, err := ca.LoadOrCreate(caDir)
	if err != nil {
		return nil, err
	}

	t, _ := template.ParseGlob("internal/templates/*.html")

	h := httpapi.New(httpapi.Deps{
		DB:        sqlDB,
		CA:        panelCA,
		PublicURL: cfg.PublicURL,
		CookieKey: []byte(cfg.CookieKey),
		Templates: t,
	})

	s := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	app := &App{cfg: cfg, db: sqlDB, ca: panelCA, server: s}
	if err := app.ensureBootstrapAdmin(ctx); err != nil {
		return nil, err
	}
	return app, nil
}

func (a *App) ListenAndServe() error {
	err := a.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *App) Shutdown(ctx context.Context) error {
	return a.server.Shutdown(ctx)
}

func (a *App) Close() {
	_ = a.db.Close()
}

func (a *App) ensureBootstrapAdmin(ctx context.Context) error {
	// If there are no users, create admin with random password and print it once.
	var cnt int
	if err := a.db.QueryRowContext(ctx, `select count(*) from users`).Scan(&cnt); err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if cnt > 0 {
		return nil
	}

	password, err := randomToken(18)
	if err != nil {
		return err
	}

	hash, err := httpapi.HashPassword(password)
	if err != nil {
		return err
	}

	_, err = a.db.ExecContext(ctx, `insert into users (id, email, password_hash, role) values (gen_random_uuid(), $1, $2, 'admin')`, "admin@local", hash)
	if err != nil {
		return fmt.Errorf("create bootstrap admin: %w", err)
	}

	// Print to stdout (installer captures / journald).
	fmt.Printf("BOOTSTRAP_ADMIN_EMAIL=admin@local\n")
	fmt.Printf("BOOTSTRAP_ADMIN_PASSWORD=%s\n", password)

	// Keep running; password is printed once.

	return nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	// url-ish token
	return hex.EncodeToString(b), nil
}
