package handler

import (
	_ "Kauth/docs"
	"github.com/gorilla/mux"
)

type Handlers struct {
	authHandler   *AuthHandler
	staticHandler *StaticHandler
}

func NewHandler(authHandler *AuthHandler, staticHandler *StaticHandler) *Handlers {
	return &Handlers{
		authHandler:   authHandler,
		staticHandler: staticHandler,
	}
}

func (h *Handlers) InitRoutes() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/api/login", h.authHandler.login).Methods("POST")

	r.HandleFunc("/oauth/authorize", h.authHandler.authorize).Methods("GET")
	r.HandleFunc("/oauth/user", h.authHandler.authorize).Methods("GET")
	r.HandleFunc("/oauth/token", h.authHandler.token).Methods("POST")
	r.HandleFunc("/forward-auth/auth", h.authHandler.forwardAuth).Methods("GET")

	//r.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)
	r.PathPrefix("/").Handler(h.staticHandler)
	return r
}
