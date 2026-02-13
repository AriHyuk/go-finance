package main

import (
	"fmt"
	"log"

	"go-finance/internal/adapter/handler/rest"
	"go-finance/internal/adapter/repository/postgres"
	"go-finance/internal/core/service"
	"go-finance/pkg/database"

	"github.com/spf13/viper"
)

func main() {
	// --- 1. LOAD CONFIGURATION ---
	viper.SetConfigFile(".env")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Println("Warning: Cannot read .env file:", err)
	}

	// Validate critical configuration (fail-fast)
	jwtSecret := viper.GetString("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("❌ FATAL: JWT_SECRET is required")
	}

	// --- 2. CONNECT TO DATABASE ---
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		viper.GetString("DB_USER"),
		viper.GetString("DB_PASSWORD"),
		viper.GetString("DB_HOST"),
		viper.GetString("DB_PORT"),
		viper.GetString("DB_NAME"),
	)

	dbPool, err := database.NewPostgresConnection(dsn)
	if err != nil {
		log.Fatalf("❌ Failed to connect to database: %v", err)
	}
	defer dbPool.Close()

	// --- 3. DEPENDENCY INJECTION (Clean Architecture Wiring) ---
	userRepo := postgres.NewUserRepository(dbPool)
	authService := service.NewAuthService(userRepo, jwtSecret)
	authHandler := rest.NewAuthHandler(authService)

	// --- 4. SETUP ROUTER & START SERVER ---
	router := rest.NewRouter(authHandler, authService, dbPool)

	port := viper.GetString("APP_PORT")
	if port == "" || port[0] != ':' {
		port = ":8080"
	}

	log.Printf("🚀 Server running on port %s", port)
	if err := router.Run(port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
