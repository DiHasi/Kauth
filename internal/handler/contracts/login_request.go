package contracts

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Scope    string `json:"scope"`
	State    string `json:"state"`
}
