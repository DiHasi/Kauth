package repository

import (
	"Kauth/internal/models"
	"fmt"
	"github.com/jmoiron/sqlx"
)

type OAuthClientRepository struct {
	db *sqlx.DB
}

func NewOAuthClientRepository(db *sqlx.DB) OAuthClientRepository {
	return OAuthClientRepository{db: db}
}

func (r *OAuthClientRepository) GetByClientID(clientId string) (*models.OAuthClient, error) {
	var client models.OAuthClient
	err := r.db.Get(&client, "SELECT * FROM oauth_clients WHERE client_id = $1", clientId)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch oauth client with id %s: %w", clientId, err)
	}
	return &client, nil
}
