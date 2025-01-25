package models

type Session struct {
	UserID      int    `json:"user_id"`
	Scope       string `json:"scope"`
	RedirectURI string `json:"redirect_uri"`
}
