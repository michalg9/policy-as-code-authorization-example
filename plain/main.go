package main

import (
	"log"
	"net/http"

	"github.com/michalg9/policy-as-code-authorization-example/internal/authz"
	"github.com/michalg9/policy-as-code-authorization-example/internal/server"
	"github.com/michalg9/policy-as-code-authorization-example/internal/users"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type authorizer struct {
	users users.Users
	roles Roles
}

func (a *authorizer) HasPermission(userID, action, asset string) bool {
	user, ok := a.users[userID]
	if !ok {
		// Unknown userID
		log.Print("Unknown user:", userID)
		return false
	}

	for _, roleName := range user.Roles {
		if role, ok := a.roles[roleName]; ok {
			resources, ok := role[action]
			if ok {
				for _, resource := range resources {
					if resource == asset {
						return true
					}
				}
			}
		} else {
			log.Printf("User '%s' has unknown role '%s'", userID, roleName)
		}
	}

	return false
}

func main() {

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Route("/api", func(r chi.Router) {
		r.With(getAuthMiddleware()).Route("/{asset}", func(r chi.Router) {
			r.Get("/", server.Handler)
			r.Post("/", server.Handler)
			r.Delete("/", server.Handler)
		})
	})
	http.ListenAndServe(":3000", r)

}

func getAuthMiddleware() func(http.Handler) http.Handler {
	users, err := users.Load()
	if err != nil {
		log.Fatal("Failed to load users:", err)
	}

	roles, err := LoadRoles()
	if err != nil {
		log.Fatal("Failed to load roles:", err)
	}

	return authz.Middleware(&authorizer{users: users, roles: roles})
}
