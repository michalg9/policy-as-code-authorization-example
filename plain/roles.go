package main

import (
	"github.com/michalg9/policy-as-code-authorization-example/internal/file"
)

type Resources []string

type Actions map[string]Resources

type Roles map[string]Actions

func LoadRoles() (Roles, error) {
	var roles Roles

	if err := file.LoadJson("./roles.json", &roles); err != nil {
		return nil, err
	}

	return roles, nil
}
