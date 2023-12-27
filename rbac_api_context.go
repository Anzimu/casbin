package casbin

import (
	"context"
	"github.com/anzimu/casbin/v2/constant"
	"github.com/anzimu/casbin/v2/errors"
	"github.com/anzimu/casbin/v2/util"
)

// AddRoleForUserCtx adds a role for a user.
// Returns false if the user already has the role (aka not affected).
func (e *Enforcer) AddRoleForUserCtx(ctx context.Context, user string, role string, domain ...string) (bool, error) {
	args := []string{user, role}
	args = append(args, domain...)
	return e.AddGroupingPolicyCtx(ctx, args)
}

// AddRolesForUserCtx adds roles for a user.
// Returns false if the user already has the roles (aka not affected).
func (e *Enforcer) AddRolesForUserCtx(ctx context.Context, user string, roles []string, domain ...string) (bool, error) {
	var rules [][]string
	for _, role := range roles {
		rule := []string{user, role}
		rule = append(rule, domain...)
		rules = append(rules, rule)
	}
	return e.AddGroupingPoliciesCtx(ctx, rules)
}

// DeleteRoleForUserCtx deletes a role for a user.
// Returns false if the user does not have the role (aka not affected).
func (e *Enforcer) DeleteRoleForUserCtx(ctx context.Context, user string, role string, domain ...string) (bool, error) {
	args := []string{user, role}
	args = append(args, domain...)
	return e.RemoveGroupingPolicyCtx(ctx, args)
}

// DeleteRolesForUserCtx deletes all roles for a user.
// Returns false if the user does not have any roles (aka not affected).
func (e *Enforcer) DeleteRolesForUserCtx(ctx context.Context, user string, domain ...string) (bool, error) {
	var args []string
	if len(domain) == 0 {
		args = []string{user}
	} else if len(domain) > 1 {
		return false, errors.ErrDomainParameter
	} else {
		args = []string{user, "", domain[0]}
	}
	return e.RemoveFilteredGroupingPolicyCtx(ctx, 0, args...)
}

// DeleteUserCtx deletes a user.
// Returns false if the user does not exist (aka not affected).
func (e *Enforcer) DeleteUserCtx(ctx context.Context, user string) (bool, error) {
	var err error
	res1, err := e.RemoveFilteredGroupingPolicyCtx(ctx, 0, user)
	if err != nil {
		return res1, err
	}

	subIndex, err := e.GetFieldIndex("p", constant.SubjectIndex)
	if err != nil {
		return false, err
	}
	res2, err := e.RemoveFilteredPolicyCtx(ctx, subIndex, user)
	return res1 || res2, err
}

// DeleteRoleCtx deletes a role.
// Returns false if the role does not exist (aka not affected).
func (e *Enforcer) DeleteRoleCtx(ctx context.Context, role string) (bool, error) {
	var err error
	res1, err := e.RemoveFilteredGroupingPolicyCtx(ctx, 1, role)
	if err != nil {
		return res1, err
	}

	subIndex, err := e.GetFieldIndex("p", constant.SubjectIndex)
	if err != nil {
		return false, err
	}
	res2, err := e.RemoveFilteredPolicyCtx(ctx, subIndex, role)
	return res1 || res2, err
}

// DeletePermissionCtx deletes a permission.
// Returns false if the permission does not exist (aka not affected).
func (e *Enforcer) DeletePermissionCtx(ctx context.Context, permission ...string) (bool, error) {
	return e.RemoveFilteredPolicyCtx(ctx, 1, permission...)
}

// AddPermissionForUserCtx adds a permission for a user or role.
// Returns false if the user or role already has the permission (aka not affected).
func (e *Enforcer) AddPermissionForUserCtx(ctx context.Context, user string, permission ...string) (bool, error) {
	return e.AddPolicyCtx(ctx, util.JoinSlice(user, permission...))
}

// AddPermissionsForUserCtx adds multiple permissions for a user or role.
// Returns false if the user or role already has one of the permissions (aka not affected).
func (e *Enforcer) AddPermissionsForUserCtx(ctx context.Context, user string, permissions ...[]string) (bool, error) {
	var rules [][]string
	for _, permission := range permissions {
		rules = append(rules, util.JoinSlice(user, permission...))
	}
	return e.AddPoliciesCtx(ctx, rules)
}

// DeletePermissionForUserCtx deletes a permission for a user or role.
// Returns false if the user or role does not have the permission (aka not affected).
func (e *Enforcer) DeletePermissionForUserCtx(ctx context.Context, user string, permission ...string) (bool, error) {
	return e.RemovePolicyCtx(ctx, util.JoinSlice(user, permission...))
}

// DeletePermissionsForUserCtx deletes permissions for a user or role.
// Returns false if the user or role does not have any permissions (aka not affected).
func (e *Enforcer) DeletePermissionsForUserCtx(ctx context.Context, user string) (bool, error) {
	subIndex, err := e.GetFieldIndex("p", constant.SubjectIndex)
	if err != nil {
		return false, err
	}
	return e.RemoveFilteredPolicyCtx(ctx, subIndex, user)
}
