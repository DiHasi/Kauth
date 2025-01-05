package models

type Scope string

const (
	ScopeUsername Scope = "name"
	ScopeID       Scope = "id"
	ScopeEmail    Scope = "email"
)

func GetAllScopes() []Scope {
	return []Scope{
		ScopeUsername,
		ScopeID,
		ScopeEmail,
	}
}
