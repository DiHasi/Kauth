package service

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

type ConfigService struct {
	db *sqlx.DB
}

func NewConfigService(db *sqlx.DB) *ConfigService {
	return &ConfigService{db: db}
}

func (s *ConfigService) InitUsers() error {
	_, err := s.db.Exec("DELETE FROM users")
	if err != nil {
		return fmt.Errorf("failed to delete users: %w", err)
	}

	users := viper.GetStringMap("users")
	for username, userData := range users {
		userMap := userData.(map[string]interface{})
		password := userMap["password"].(string)

		_, err := s.db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, password)
		if err != nil {
			return fmt.Errorf("failed to insert user %s: %w", username, err)
		}
	}

	return nil
}
