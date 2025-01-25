package handler

import (
	"Kauth/internal/handler/contracts"
	"Kauth/internal/models"
	"Kauth/internal/service"
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AuthHandler struct {
	authService      *service.AuthService
	cookieEncryption *service.CookieEncryptionService
}

func NewAuthHandler(authService *service.AuthService, cookieEncryption *service.CookieEncryptionService) *AuthHandler {
	return &AuthHandler{authService: authService,
		cookieEncryption: cookieEncryption}
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *AuthHandler) login(w http.ResponseWriter, r *http.Request) {

	var req = new(contracts.LoginRequest)

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := h.authService.Login(req.Username, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if req.State == "" {
		cookie, err := h.cookieEncryption.Encrypt(
			map[string]string{
				"username": user.Username,
			})

		if err != nil {
			log.Println(err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "AuthCookie",
			Value:    cookie,
			Domain:   viper.GetString("forwardauth.domain"),
			Expires:  time.Now().Add(1 * time.Hour),
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
		})
		//w.Header().Set("Access-Control-Allow-Credentials", "true")
		err = json.NewEncoder(w).Encode(map[string]string{})
		return
	}

	code, err := h.authService.GenerateCode()
	if err != nil {
		log.Println(err)
		return
	}

	err = h.authService.SaveAuthCode(user.ID, code, req.Scope)

	if err != nil {
		log.Println(err)
		return
	}

	err = json.NewEncoder(w).Encode(map[string]string{
		"code": code,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *AuthHandler) authorize(w http.ResponseWriter, r *http.Request) {
	accessToken := r.Header.Get("Authorization")
	if accessToken != "" {
		err := h.authService.ValidateToken(accessToken)
		if err != nil {
			_ = h.authService.DeleteSession(accessToken)
			http.Error(w, "Token expired", http.StatusUnauthorized)
		}
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte("OK"))
		if err != nil {
			return
		}
		return
	}

	queryParams := r.URL.Query()

	responseType := queryParams.Get("response_type")
	redirectUri := queryParams.Get("redirect_uri")
	scope := queryParams.Get("scope")
	state := queryParams.Get("state")
	clientId := queryParams.Get("client_id")

	if responseType != "code" {
		http.Error(w, "Invalid response type", http.StatusInternalServerError)
	}

	http.Redirect(w, r, fmt.Sprintf("/login?redirect_uri=%s&scope=%s&state=%s&client_name=%s", redirectUri, scope, state, clientId), http.StatusFound)
}

func (h *AuthHandler) token(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	clientId := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	grantType := r.FormValue("grant_type")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" || grantType == "" || redirectURI == "" || clientId == "" || clientSecret == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	userID, scope, err := h.authService.GetUserInfoByAuthCode(code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	accessToken, err := h.authService.GenerateToken(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.authService.DeleteUserInfoByAuthCode(code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session := &models.Session{
		UserID:      userID,
		Scope:       scope,
		RedirectURI: redirectURI,
	}

	err = h.authService.SaveSession(accessToken, session)
	if err != nil {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"access_token": accessToken,
		"scope":        scope,
		"token_type":   "bearer",
	}

	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

func (h *AuthHandler) user(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")

	err := h.authService.ValidateToken(token)
	if err != nil {
		log.Printf("Error validating token: %v\n", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	accessToken := strings.TrimPrefix(token, "Bearer ")
	session, err := h.authService.GetSession(accessToken)
	if err != nil {
		return
	}

	scopeFields := strings.Fields(session.Scope)

	user, err := h.authService.GetUserById(session.UserID)
	if err != nil {
		return
	}

	filteredFields, err := user.FilterFields(strings.Join(scopeFields, " "))
	if err != nil {
		log.Printf("Error filtering fields: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(filteredFields)
	if err != nil {
		log.Printf("Error encoding response: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *AuthHandler) forwardAuth(w http.ResponseWriter, r *http.Request) {
	authCookie, err := r.Cookie("AuthCookie")
	if err != nil || authCookie.Value == "" {
		originalProtocol := r.Header.Get("X-Forwarded-Proto")
		if originalProtocol == "" {
			originalProtocol = "http"
		}

		originalHost := r.Header.Get("X-Forwarded-Host")
		if originalHost == "" {
			originalHost = "localhost"
		}

		originalUrl := r.Header.Get("X-Forwarded-Uri")
		if originalUrl == "" {
			originalUrl = "/"
		}

		originalMethod := r.Header.Get("X-Forwarded-Method")
		if originalMethod == "" {
			originalMethod = "GET"
		}

		authUrl := viper.GetString("forwardauth.auth-url")
		if authUrl == "" {
			log.Fatal("forwardauth.auth-url is empty")
		}
		redirectUrl := fmt.Sprintf(
			"%s?redirect_uri=%s://%s%s&method=%s",
			authUrl,
			url.QueryEscape(originalProtocol),
			url.QueryEscape(originalHost),
			url.QueryEscape(originalUrl),
			url.QueryEscape(originalMethod),
		)

		http.Redirect(w, r, redirectUrl, http.StatusFound)
		return
	}

	cookieData, err := h.cookieEncryption.Decrypt(authCookie.Value)
	if err != nil || cookieData == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
}
