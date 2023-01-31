package rbac_opa

# Pairs of roles that no user can be assigned to simultaneously
sod_roles := [
    ["engineering", "hr"],
]

sod_violation {
    # grab one role for a user
    role1 :=  input.users[input.user].roles[_]
    # grab another role for that same user
    role2 :=  input.users[input.user].roles[_]
    # check if those roles are forbidden by SOD
    sod_roles[_] == [role1, role2]
}


# logic that implements RBAC.
default allow = false
allow {
    # lookup the list of roles for the user
    roles := input.users[input.user].roles

    # for each role in that list
    r := roles[_]
    # lookup the permissions list for role r
    permissions := input.role_permissions[r]
    # for each permission
    p := permissions[_]
    # check if the permission granted to r matches the user's request
    p == {"action": input.action, "object": input.object}
}
