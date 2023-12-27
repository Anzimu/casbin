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

// AddRoleForUserInDomainCtx adds a role for a user inside a domain.
// Returns false if the user already has the role (aka not affected).
func (e *SyncedContextEnforcer) AddRoleForUserInDomainCtx(ctx context.Context, user string, role string, domain string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddRoleForUserInDomainCtx(ctx, user, role, domain)
}

// DeleteRoleForUserInDomainCtx deletes a role for a user inside a domain.
// Returns false if the user does not have the role (aka not affected).
func (e *SyncedContextEnforcer) DeleteRoleForUserInDomainCtx(ctx context.Context, user string, role string, domain string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.DeleteRoleForUserInDomainCtx(ctx, user, role, domain)
}

// DeleteRolesForUserInDomainCtx deletes all roles for a user inside a domain.
// Returns false if the user does not have any roles (aka not affected).
func (e *SyncedContextEnforcer) DeleteRolesForUserInDomainCtx(ctx context.Context, user string, domain string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.DeleteRolesForUserInDomainCtx(ctx, user, domain)
}

// DeleteAllUsersByDomainCtx would delete all users associated with the domain.
func (e *SyncedContextEnforcer) DeleteAllUsersByDomainCtx(ctx context.Context, domain string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.DeleteAllUsersByDomainCtx(ctx, domain)
}

// DeleteDomainsCtx would delete all associated users and roles.
// It would delete all domains if parameter is not provided.
func (e *SyncedContextEnforcer) DeleteDomainsCtx(ctx context.Context, domains ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.DeleteDomainsCtx(ctx, domains...)
}
