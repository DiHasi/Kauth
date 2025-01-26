package main

import (
	database "Kauth/internal/db"
	"Kauth/internal/handler"
	"Kauth/internal/models"
	"Kauth/internal/repository"
	"Kauth/internal/service"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"
	"log"
	"os"
	"path/filepath"
)

func main() {
	err := initConfig()
	if err != nil {
		log.Println("Error:", err)
	}

	db, err := database.Connect(database.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Username: os.Getenv("DB_USERNAME"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
	})

	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	driver, err := postgres.WithInstance(db.DB, &postgres.Config{})
	if err != nil {
		log.Fatal(err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres", driver)
	if err != nil {
		log.Fatal("migration...: ", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Fatal(err)
	}

	configService := service.NewConfigService(db)
	if err := configService.InitUsers(); err != nil {
		log.Fatal("Failed to initialize users:", err)
	}

	if err := configService.InitOAuthClients(); err != nil {
		log.Fatal("Failed to initialize users:", err)
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")),
	})

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		return
	}
	staticDir := filepath.Join(cwd, "web", "dist")

	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		log.Fatal("SECRET_KEY is null")
	}

	userRepo := repository.NewUserRepository(db)
	oauthRepo := repository.NewOAuthClientRepository(db)

	cookieEncryptionService, err := service.NewCookieEncryptionService(secretKey)
	if err != nil {
		log.Fatal(err)
	}
	authService := service.NewAuthService(userRepo, oauthRepo, redisClient, cookieEncryptionService, secretKey)
	authHandler := handler.NewAuthHandler(authService, cookieEncryptionService)
	staticHandler := handler.NewStaticHandler(staticDir)
	handlers := handler.NewHandler(authHandler, staticHandler)

	srv := new(models.Server)
	fmt.Println("Starting server on port:", os.Getenv("APP_PORT"))
	if err := srv.Run(os.Getenv("APP_PORT"), handlers.InitRoutes()); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Server started on port %s\n", os.Getenv("PORT"))
}

func initConfig() error {
	viper.AddConfigPath("configs")
	viper.SetConfigName("configuration")
	if err := viper.ReadInConfig(); err != nil {
		return err
	}

	viper.SetConfigName("users")
	if err := viper.MergeInConfig(); err != nil {
		return err
	}

	return nil
}
