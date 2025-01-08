package handler

import (
	"Kauth/internal/handler/contracts"
	"Kauth/internal/service"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// @Summary Register
// @Description Register a new user
// @Tags auth
// @Accept json
// @Produce json
// @Param registerRequest body RegisterRequest true "Register request"
// @Success 201 {string} string "Created"
// @Router /api/register [post]
func (h *AuthHandler) register(w http.ResponseWriter, r *http.Request) {
	var req = new(RegisterRequest)

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := h.authService.Register(req.Username, req.Password)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// @Summary Login
// @Description Login with username and password
// @Tags auth
// @Accept json
// @Produce json
// @Param loginRequest body contracts.LoginRequest true "Login request"
// @Success 200 {object} map[string]string
// @Failure 400 {string} string "Invalid request"
// @Router /api/login [post]
func (h *AuthHandler) login(w http.ResponseWriter, r *http.Request) {

	var req = new(contracts.LoginRequest)

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	code, err := h.authService.Login(req.Username, req.Password, req.Scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// TODO: make response type
	err = json.NewEncoder(w).Encode(map[string]string{
		"code": code,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *AuthHandler) refreshToken(w http.ResponseWriter, r *http.Request) {
}

// @Summary Authorize
// @Description Authorize the user
// @Tags oauth
// @Accept json
// @Produce json
// @Param response_type query string true "Response type"
// @Param client_id query string true "Client ID"
// @Param redirect_uri query string true "Redirect URI"
// @Param scope query string true "Scope"
// @Param state query string true "State"
// @Success 302 {string} string "Redirect"
// @Failure 400 {string} string "Invalid request"
// @Router /oauth/authorize [get]
func (h *AuthHandler) authorize(w http.ResponseWriter, r *http.Request) {
	accessToken := r.Header.Get("Authorization")
	if accessToken != "" {
		_, claims, err := h.authService.ValidateToken(accessToken)
		if err != nil {
			http.Error(w, "Token expired", http.StatusUnauthorized)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(claims); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
		return
	}

	queryParams := r.URL.Query()

	responseType := queryParams.Get("response_type")
	redirectUri := queryParams.Get("redirect_uri")
	scope := queryParams.Get("scope")
	state := queryParams.Get("state")

	if responseType != "code" {
		http.Error(w, "Invalid response type", http.StatusInternalServerError)
	}

	http.Redirect(w, r, fmt.Sprintf("/login?redirect_uri=%s&scope=%s&state=%s", redirectUri, scope, state), http.StatusFound)
}

// @Summary Get Token
// @Description Get access and refresh tokens
// @Tags oauth
// @Accept json
// @Produce json
// @Param tokenRequest body contracts.TokenRequest true "Token request"
// @Success 200 {object} map[string]string
// @Failure 400 {string} string "Invalid request"
// @Failure 401 {string} string "Unauthorized"
// @Router /oauth/token [post]
func (h *AuthHandler) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Println("Form parse error:", err)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	grantType := r.FormValue("grant_type")
	redirectURI := r.FormValue("redirect_uri")

	if code == "" || grantType == "" || redirectURI == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	userID, scope, err := h.authService.GetUserInfoByAuthCode(code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	accessToken, err := h.authService.GenerateToken(userID, scope)
	if err != nil {
		log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		log.Println(err.Error())
		return
	}
}

func (h *AuthHandler) user(w http.ResponseWriter, r *http.Request) {

	token := r.Header.Get("Authorization")
	user, _, err := h.authService.ValidateToken(token)
	if err != nil {
		log.Println(err.Error())
		return
	}

	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"name": user.ID,
	})
	if err != nil {
		log.Println(err.Error())
		return
	}
}

func (h *AuthHandler) forwardAuth(w http.ResponseWriter, r *http.Request) {
}
