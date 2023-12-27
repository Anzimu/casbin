// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package casbin

import "context"

// AddRoleForUserCtx adds a role for a user.
// Returns false if the user already has the role (aka not affected).
func (e *SyncedContextEnforcer) AddRoleForUserCtx(ctx context.Context, user string, role string, domain ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddRoleForUserCtx(ctx, user, role, domain...)
}

// AddRolesForUserCtx adds roles for a user.
// Returns false if the user already has the roles (aka not affected).
func (e *SyncedContextEnforcer) AddRolesForUserCtx(ctx context.Context, user string, roles []string, domain ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddRolesForUserCtx(ctx, user, roles, domain...)
}

// DeleteRoleForUserCtx deletes a role for a user.
// Returns false if the user does not have the role (aka not affected).
func (e *SyncedContextEnforcer) DeleteRoleForUserCtx(ctx context.Context, user string, role string, domain ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.DeleteRoleForUserCtx(ctx, user, role, domain...)
}

// DeleteRolesForUserCtx deletes all roles for a user.
// Returns false if the user does not have any roles (aka not affected).
func (e *SyncedContextEnforcer) DeleteRolesForUserCtx(ctx context.Context, user string, domain ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.DeleteRolesForUserCtx(ctx, user, domain...)
}

// DeleteUserCtx deletes a user.
// Returns false if the user does not exist (aka not affected).
func (e *SyncedContextEnforcer) DeleteUserCtx(ctx context.Context, user string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.DeleteUserCtx(ctx, user)
}

// DeleteRoleCtx deletes a role.
// Returns false if the role does not exist (aka not affected).
func (e *SyncedContextEnforcer) DeleteRoleCtx(ctx context.Context, role string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.DeleteRoleCtx(ctx, role)
}

// DeletePermissionCtx deletes a permission.
// Returns false if the permission does not exist (aka not affected).
func (e *SyncedContextEnforcer) DeletePermissionCtx(ctx context.Context, permission ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.DeletePermissionCtx(ctx, permission...)
}

// AddPermissionForUserCtx adds a permission for a user or role.
// Returns false if the user or role already has the permission (aka not affected).
func (e *SyncedContextEnforcer) AddPermissionForUserCtx(ctx context.Context, user string, permission ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddPermissionForUserCtx(ctx, user, permission...)
}

// AddPermissionsForUserCtx adds permissions for a user or role.
// Returns false if the user or role already has the permissions (aka not affected).
func (e *SyncedContextEnforcer) AddPermissionsForUserCtx(ctx context.Context, user string, permissions ...[]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddPermissionsForUserCtx(ctx, user, permissions...)
}

// DeletePermissionForUserCtx deletes a permission for a user or role.
// Returns false if the user or role does not have the permission (aka not affected).
func (e *SyncedContextEnforcer) DeletePermissionForUserCtx(ctx context.Context, user string, permission ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.DeletePermissionForUserCtx(ctx, user, permission...)
}

// DeletePermissionsForUserCtx deletes permissions for a user or role.
// Returns false if the user or role does not have any permissions (aka not affected).
func (e *SyncedContextEnforcer) DeletePermissionsForUserCtx(ctx context.Context, user string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.DeletePermissionsForUserCtx(ctx, user)
}
