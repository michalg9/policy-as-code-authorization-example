package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/michalg9/policy-as-code-authorization-example/internal/authz"
	"github.com/michalg9/policy-as-code-authorization-example/internal/server"
	"github.com/michalg9/policy-as-code-authorization-example/internal/users"

	"github.com/open-policy-agent/opa/rego"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type rolePermissions map[string][]map[string]string
type authorizer struct {
	users           users.Users
	rolePermissions rolePermissions
	policy          string
}

type policyInput struct {
	User   string `json:"user"`
	Action string `json:"action"`
	Object string `json:"object"`

	RolePermissions rolePermissions `json:"role_permissions"`
	Users           users.Users     `json:"users"`
}

func (a *authorizer) HasPermission(userID, action, asset string) bool {
	ctx := context.Background()

	user, ok := a.users[userID]
	if !ok {
		// Unknown userID
		log.Print("Unknown user:", userID)
		return false
	}

	base := rego.New(rego.Query("data.rbac_opa.allow"),
		rego.Module("policy", a.policy))

	preparedQuery, err := base.PrepareForEval(ctx)
	if err != nil {
		log.Printf("%v", err)
		return false
	}

	input := policyInput{
		User:            user.ID,
		Action:          action,
		Object:          asset,
		RolePermissions: a.rolePermissions,
		Users:           a.users,
	}

	result, err := preparedQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Printf("%v", err)
		return false
	}

	return result.Allowed()
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
	authPolicy, err := os.ReadFile("./rbac_policy.rego")
	if err != nil {
		log.Fatal("Failed to read auth policy:", err)
	}

	rolePermissionsFile, err := os.Open("./role_permissions.json")
	if err != nil {
		log.Fatal("Failed to open role permissions file:", err)
	}

	var rolePermissions map[string][]map[string]string
	if err := json.NewDecoder(rolePermissionsFile).Decode(&rolePermissions); err != nil {
		log.Fatal("Failed to decode role permissions:", err)
	}

	users, err := users.Load()
	if err != nil {
		log.Fatal("Failed to load users:", err)
	}

	return authz.Middleware(&authorizer{users: users, policy: string(authPolicy), rolePermissions: rolePermissions})
}
