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
		Host:     viper.GetString("db.host"),
		Port:     viper.GetString("db.port"),
		Username: viper.GetString("db.username"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   viper.GetString("db.dbname"),
		SSLMode:  viper.GetString("db.sslmode"),
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
		log.Fatal(err)
	}

	configService := service.NewConfigService(db)
	if err := configService.InitUsers(); err != nil {
		log.Fatal("Failed to initialize users:", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Fatal(err)
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", viper.GetString("db.redisHost"), viper.GetString("db.redisPort")),
	})

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		return
	}
	staticDir := filepath.Join(cwd, "web", "dist")

	userRepo := repository.NewUserRepository(db)
	services := service.NewAuthService(userRepo, viper.GetString("secret_key"), redisClient)
	authHandler := handler.NewAuthHandler(services)
	staticHandler := handler.NewStaticHandler(staticDir)
	handlers := handler.NewHandler(authHandler, staticHandler)

	srv := new(models.Server)
	fmt.Println("Starting server...")
	if err := srv.Run(os.Getenv("PORT"), handlers.InitRoutes()); err != nil {
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
