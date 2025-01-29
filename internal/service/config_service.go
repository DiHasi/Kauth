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
	_, err := s.db.Exec("DELETE FROM user_roles")
	if err != nil {
		return fmt.Errorf("failed to delete user roles: %w", err)
	}

	_, err = s.db.Exec("DELETE FROM roles")
	if err != nil {
		return fmt.Errorf("failed to delete roles: %w", err)
	}

	_, err = s.db.Exec("DELETE FROM users")
	if err != nil {
		return fmt.Errorf("failed to delete users: %w", err)
	}

	_, err = s.db.Exec("ALTER SEQUENCE users_id_seq RESTART WITH 1")
	if err != nil {
		return fmt.Errorf("failed to reset users sequence: %w", err)
	}

	_, err = s.db.Exec("ALTER SEQUENCE roles_id_seq RESTART WITH 1")
	if err != nil {
		return fmt.Errorf("failed to reset roles sequence: %w", err)
	}

	users := viper.GetStringMap("users")

	roleSet := make(map[string]struct{})
	for _, userData := range users {
		userMap := userData.(map[string]interface{})
		groups, ok := userMap["groups"].([]interface{})
		if ok {
			for _, group := range groups {
				roleSet[group.(string)] = struct{}{}
			}
		}
	}

	roleIDs := make(map[string]int)
	for role := range roleSet {
		var roleID int
		err := s.db.QueryRow("INSERT INTO roles (name) VALUES ($1) RETURNING id", role).Scan(&roleID)
		if err != nil {
			return fmt.Errorf("failed to insert role %s: %w", role, err)
		}
		roleIDs[role] = roleID
	}

	for username, userData := range users {
		userMap := userData.(map[string]interface{})
		password := userMap["password"].(string)

		var userID int
		err := s.db.QueryRow("INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id", username, password).Scan(&userID)
		if err != nil {
			return fmt.Errorf("failed to insert user %s: %w", username, err)
		}

		groups, ok := userMap["groups"].([]interface{})
		if !ok {
			continue
		}
		for _, group := range groups {
			roleID := roleIDs[group.(string)]
			_, err := s.db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)", userID, roleID)
			if err != nil {
				return fmt.Errorf("failed to associate role %s with user %s: %w", group, username, err)
			}
		}
	}

	return nil
}

func (s *ConfigService) InitOAuthClients() error {
	_, err := s.db.Exec("DELETE FROM oauth_clients")
	if err != nil {
		return fmt.Errorf("failed to delete oauth clients: %w", err)
	}

	_, err = s.db.Exec("ALTER SEQUENCE oauth_clients_id_seq RESTART WITH 1")
	if err != nil {
		return fmt.Errorf("failed to reset oauth clients sequence: %w", err)
	}

	clients := viper.GetStringMap("oauth.clients")
	for name, clientData := range clients {
		clientMap := clientData.(map[string]interface{})
		clientID := clientMap["client_id"].(string)
		clientSecret := clientMap["client_secret"].(string)
		homepageURL := clientMap["homepageurl"].(string)

		_, err := s.db.Exec(
			"INSERT INTO oauth_clients (name, client_id, client_secret, homepage_url) VALUES ($1, $2, $3, $4)",
			name, clientID, clientSecret, homepageURL,
		)
		if err != nil {
			return fmt.Errorf("failed to insert oauth client %s: %w", name, err)
		}
	}

	return nil
}
