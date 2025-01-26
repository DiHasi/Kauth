package repository

import (
	"Kauth/internal/models"
	"github.com/jmoiron/sqlx"
)

type UserRepository interface {
	GetByID(id int) (*models.User, error)
	GetByUsername(username string) (*models.User, error)
}

type userRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) GetByID(id int) (*models.User, error) {
	var user models.User
	if err := r.db.Get(&user, "SELECT * FROM users WHERE id = $1", id); err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetByUsername(username string) (*models.User, error) {
	var user models.User
	if err := r.db.Get(&user, "SELECT * FROM users WHERE username = $1", username); err != nil {
		return nil, err
	}
	return &user, nil
}
