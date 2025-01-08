package service

import (
	"Kauth/internal/models"
	"Kauth/internal/repository"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"time"
)

type AuthService struct {
	userRepo    repository.UserRepository
	redisClient *redis.Client
	secretKey   string
}

var ErrTokenExpired = errors.New("token expired")

func NewAuthService(userRepo repository.UserRepository, secretKey string, redisClient *redis.Client) *AuthService {
	return &AuthService{userRepo: userRepo, secretKey: secretKey, redisClient: redisClient}
}

func (s *AuthService) Register(username, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := &models.User{
		Username: username,
		Password: string(hashedPassword),
	}

	return s.userRepo.Create(user)
}

func (s *AuthService) Login(username, password, scope string) (string, error) {
	user, err := s.userRepo.GetByUsername(username)
	if err != nil {
		return "", err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return "", err
	}

	code, err := s.GenerateCode()
	if err != nil {
		return "", err
	}

	err = s.SaveAuthCode(user.ID, code, scope)
	if err != nil {
		return "", err
	}

	return code, nil
}

func (s *AuthService) ValidateToken(accessToken string) (*models.User, *jwt.MapClaims, error) {
	accessToken = strings.TrimPrefix(accessToken, "Bearer ")

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.secretKey), nil
	})
	if err != nil {
		if err.(*jwt.ValidationError).Errors == jwt.ValidationErrorExpired {
			return nil, nil, ErrTokenExpired
		}
		return nil, nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, nil, errors.New("invalid token")
	}

	userID := int(claims["user_id"].(float64))
	user, err := s.userRepo.GetByID(userID)
	return user, &claims, nil
}

func (s *AuthService) GetUserInfoByAuthCode(code string) (int, string, error) {
	jsonData, err := s.redisClient.Get(context.Background(), code).Result()
	if err != nil {
		return 0, "", err
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return 0, "", fmt.Errorf("ошибка десериализации данных: %w", err)
	}

	userID, ok := data["user_id"].(float64)
	if !ok {
		return 0, "", errors.New("неверный формат user_id")
	}

	scope, ok := data["scope"].(string)
	if !ok {
		return 0, "", errors.New("неверный формат scope")
	}

	return int(userID), scope, nil
}

func (s *AuthService) GenerateCode() (string, error) {
	code := make([]byte, 32)
	if _, err := rand.Read(code); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(code), nil
}

func (s *AuthService) SaveAuthCode(userID int, code, scope string) error {
	expiry := time.Minute * 10

	data := map[string]interface{}{
		"user_id": userID,
		"scope":   scope,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return errors.New("json marshal error")
	}

	return s.redisClient.Set(context.Background(), code, jsonData, expiry).Err()
}

func (s *AuthService) GenerateToken(userID int, scope string) (string, error) {

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return "", fmt.Errorf("user not found: %v", err)
	}

	validScopes := models.GetAllScopes()
	scopeMap := make(map[string]bool)
	for _, s := range validScopes {
		scopeMap[string(s)] = true
	}

	scopes := strings.Split(scope, " ")
	for _, s := range scopes {
		if !scopeMap[s] {
			return "", fmt.Errorf("invalid scope: %s", s)
		}
	}

	claims := jwt.MapClaims{
		"user_id": float64(userID),
		"scope":   strings.Join(scopes, ","),
		"exp":     time.Now().Add(time.Hour * 4).Unix(),
	}

	for _, s := range scopes {
		switch s {
		case "name":
			claims["name"] = user.Username
		}

	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(s.secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *AuthService) ExchangeToken(code string) (string, error) {
	userID, scope, err := s.GetUserInfoByAuthCode(code)
	if err != nil {
		return "", errors.New("invalid code")
	}

	accessToken, err := s.GenerateToken(userID, scope)
	if err != nil {
		return "", errors.New("error generating token")
	}
	return accessToken, nil
}
