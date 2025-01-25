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
	userRepo         repository.UserRepository
	redisClient      *redis.Client
	cookieEncryption *CookieEncryptionService
	secretKey        string
}

func NewAuthService(userRepo repository.UserRepository, redisClient *redis.Client, cookieEncryption *CookieEncryptionService, secretKey string) *AuthService {
	return &AuthService{userRepo: userRepo, redisClient: redisClient, cookieEncryption: cookieEncryption, secretKey: secretKey}
}

var ErrTokenExpired = errors.New("token expired")

func (s *AuthService) Login(username, password string) (*models.User, error) {
	user, err := s.userRepo.GetByUsername(username)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *AuthService) ValidateToken(accessToken string) error {
	accessToken = strings.TrimPrefix(accessToken, "Bearer ")

	_, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.secretKey), nil
	})
	if err != nil {
		var jwtErr *jwt.ValidationError
		if errors.As(err, &jwtErr) && jwtErr.Errors == jwt.ValidationErrorExpired {
			return ErrTokenExpired
		}
		return err
	}

	return nil
}

func (s *AuthService) GetUserInfoByAuthCode(code string) (int, string, error) {
	jsonData, err := s.redisClient.Get(context.Background(), code).Result()
	if err != nil {
		return 0, "", err
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &data); err != nil {
		return 0, "", err
	}

	userID, ok := data["user_id"].(float64)
	if !ok {
		return 0, "", err
	}

	scope, ok := data["scope"].(string)
	if !ok {
		return 0, "", err
	}

	return int(userID), scope, nil
}

func (s *AuthService) DeleteUserInfoByAuthCode(code string) error {
	err := s.redisClient.Del(context.Background(), code).Err()
	if err != nil {
		return err
	}
	return nil
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

func (s *AuthService) GenerateToken(userID int) (string, error) {

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return "", fmt.Errorf("user not found: %v", err)
	}

	validScopes := models.GetAllScopes()
	scopeMap := make(map[string]bool)
	for _, s := range validScopes {
		scopeMap[string(s)] = true
	}

	//scopes := strings.Split(scope, " ")
	//for _, s := range scopes {
	//	if !scopeMap[s] {
	//		return "", fmt.Errorf("invalid scope: %s", s)
	//	}
	//}

	claims := jwt.MapClaims{
		"user_id": float64(userID),
		"name":    user.Username,
		"exp":     time.Now().Add(time.Hour * 4).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(s.secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *AuthService) GetUserById(id int) (*models.User, error) {
	user, err := s.userRepo.GetByID(id)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *AuthService) SaveSession(accessToken string, session *models.Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	err = s.redisClient.Set(context.Background(), accessToken, data, time.Hour*4).Err()
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthService) GetSession(accessToken string) (*models.Session, error) {
	data, err := s.redisClient.Get(context.Background(), accessToken).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	var session models.Session
	err = json.Unmarshal([]byte(data), &session)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (s *AuthService) DeleteSession(accessToken string) error {
	return s.redisClient.Del(context.Background(), accessToken).Err()
}
