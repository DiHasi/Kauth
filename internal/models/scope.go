package models

type Scope string

const (
	ScopeUsername Scope = "name"
	ScopeID       Scope = "id"
	ScopeEmail    Scope = "email"
	ScopeGroups   Scope = "groups"
)

func GetAllScopes() []Scope {
	return []Scope{
		ScopeUsername,
		ScopeID,
		ScopeEmail,
		ScopeGroups,
	}
}
