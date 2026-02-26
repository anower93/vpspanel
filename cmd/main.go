package main

import (
	"log"
	"vpspanel/internal/handlers"
	"vpspanel/internal/middleware"
	"vpspanel/internal/services"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.SetTrustedProxies(nil)

	config, err := services.LoadConfig("config.yaml")
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	authService := services.NewAuthService(config)
	handlers := handlers.NewHandlers(authService, config)

	middleware.Setup(r, authService)

	r.GET("/", handlers.Home)
	r.GET("/login", handlers.LoginPage)
	r.POST("/login", handlers.Login)
	r.GET("/logout", handlers.Logout)

	admin := r.Group("/admin")
	admin.Use(middleware.AuthRequired(authService))
	{
		admin.GET("/dashboard", handlers.Dashboard)
		admin.GET("/system", handlers.SystemInfo)
		admin.GET("/processes", handlers.Processes)
		admin.POST("/processes/kill/:pid", handlers.KillProcess)
		admin.GET("/files/*path", handlers.FileManager)
		admin.POST("/files/upload", handlers.UploadFile)
		admin.POST("/files/create", handlers.CreateFile)
		admin.POST("/files/delete", handlers.DeleteFile)
		admin.POST("/files/rename", handlers.RenameFile)
		admin.GET("/terminal", handlers.Terminal)
		admin.POST("/terminal/exec", handlers.TerminalExec)
		admin.GET("/nginx", handlers.NginxManager)
		admin.POST("/nginx/reload", handlers.NginxReload)
		admin.POST("/nginx/restart", handlers.NginxRestart)
		admin.GET("/apache", handlers.ApacheManager)
		admin.POST("/apache/reload", handlers.ApacheReload)
		admin.POST("/apache/restart", handlers.ApacheRestart)
		admin.GET("/mysql", handlers.MySQLManager)
		admin.POST("/mysql/restart", handlers.MySQLRestart)
		admin.GET("/mysql/databases", handlers.MySQLDatabases)
		admin.POST("/mysql/create-db", handlers.CreateDatabase)
		admin.POST("/mysql/drop-db", handlers.DropDatabase)
		admin.GET("/postgres", handlers.PostgresManager)
		admin.POST("/postgres/restart", handlers.PostgresRestart)
		admin.GET("/dns", handlers.DNSManager)
		admin.POST("/dns/create-zone", handlers.CreateDNSZone)
		admin.POST("/dns/delete-zone", handlers.DeleteDNSZone)
		admin.GET("/services", handlers.Services)
		admin.POST("/services/restart", handlers.RestartService)
	}

	r.Static("/static", "./internal/static")
	r.LoadHTMLGlob("./internal/templates/**/*.html")

	port := config.Server.Port
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
