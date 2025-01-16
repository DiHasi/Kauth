package models

import (
	"errors"
	"reflect"
	"strings"
)

type User struct {
	ID       int      `db:"id" json:"user_id" scope:"user_id"`
	Username string   `db:"username" json:"name" scope:"name"`
	Password string   `db:"password" json:"password"`
	Groups   []string `db:"groups" scope:"groups"`
}

func (u *User) FilterFields(scope string) (map[string]interface{}, error) {
	scopeFields := strings.Fields(scope)
	if len(scopeFields) == 0 {
		return nil, errors.New("scope cannot be empty")
	}

	scopeSet := make(map[string]bool)
	for _, field := range scopeFields {
		scopeSet[field] = true
	}

	result := make(map[string]interface{})

	val := reflect.ValueOf(*u)
	typ := reflect.TypeOf(*u)

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("scope")

		if scopeSet[tag] {
			result[tag] = val.Field(i).Interface()
		}
	}

	return result, nil
}
