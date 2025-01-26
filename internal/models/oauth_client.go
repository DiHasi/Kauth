package models

type OAuthClient struct {
	ID           int    `db:"id"`
	Name         string `db:"name"`
	ClientID     string `db:"client_id"`
	ClientSecret string `db:"client_secret"`
	HomepageURL  string `db:"homepage_url"`
}
