package main

import (
	"log"
	"time"
	"vpspanel/internal/handlers"
	"vpspanel/internal/middleware"
	"vpspanel/internal/services"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.SetTrustedProxies(nil)

	config, err := services.LoadConfig("config/config.yaml")
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	authService := services.NewAuthService(config)
	handlers := handlers.NewHandlers(authService, config)

	middleware.Setup(r, authService, config)
	loginLimiter := middleware.NewRateLimiter(10, time.Minute)

	r.GET("/", handlers.Home)
	r.GET("/login", handlers.LoginPage)
	r.POST("/login", middleware.RateLimit(loginLimiter), handlers.Login)
	r.GET("/logout", handlers.Logout)

	admin := r.Group("/admin")
	admin.Use(middleware.AuthRequired(authService))
	{
		admin.GET("/dashboard", handlers.Dashboard)
		admin.GET("/system", handlers.SystemInfo)
		admin.GET("/processes", handlers.Processes)
		admin.GET("/nginx", handlers.NginxManager)
		admin.GET("/apache", handlers.ApacheManager)
		admin.GET("/mysql", handlers.MySQLManager)
		admin.GET("/postgres", handlers.PostgresManager)
		admin.GET("/dns", handlers.DNSManager)
		admin.GET("/services", handlers.Services)
	}

	unsafe := admin.Group("")
	unsafe.Use(middleware.RequireUnsafe(config))
	{
		unsafe.POST("/processes/kill/:pid", handlers.KillProcess)
		unsafe.GET("/files/*path", handlers.FileManager)
		unsafe.POST("/files/upload", handlers.UploadFile)
		unsafe.POST("/files/create", handlers.CreateFile)
		unsafe.POST("/files/delete", handlers.DeleteFile)
		unsafe.POST("/files/rename", handlers.RenameFile)
		unsafe.GET("/terminal", handlers.Terminal)
		unsafe.POST("/terminal/exec", handlers.TerminalExec)
		unsafe.POST("/nginx/reload", handlers.NginxReload)
		unsafe.POST("/nginx/restart", handlers.NginxRestart)
		unsafe.POST("/apache/reload", handlers.ApacheReload)
		unsafe.POST("/apache/restart", handlers.ApacheRestart)
		unsafe.POST("/mysql/restart", handlers.MySQLRestart)
		unsafe.GET("/mysql/databases", handlers.MySQLDatabases)
		unsafe.POST("/mysql/create-db", handlers.CreateDatabase)
		unsafe.POST("/mysql/drop-db", handlers.DropDatabase)
		unsafe.POST("/postgres/restart", handlers.PostgresRestart)
		unsafe.POST("/dns/create-zone", handlers.CreateDNSZone)
		unsafe.POST("/dns/delete-zone", handlers.DeleteDNSZone)
		unsafe.POST("/services/restart", handlers.RestartService)
	}

	r.Static("/static", "./internal/static")
	// filepath.Glob does not support **; templates live in one directory.
	r.LoadHTMLGlob("./internal/templates/*.html")

	port := config.Server.Port
	if port == "" {
		port = "8080"
	}
	host := config.Server.Host
	if host == "" {
		host = "127.0.0.1"
	}
	addr := host + ":" + port
	log.Printf("Server starting on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
