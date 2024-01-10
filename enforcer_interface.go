// Copyright 2019 The casbin Authors. All Rights Reserved.
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

import (
	"context"
	"github.com/anzimu/casbin/v2/effector"
	"github.com/anzimu/casbin/v2/model"
	"github.com/anzimu/casbin/v2/persist"
	"github.com/anzimu/casbin/v2/rbac"
	"github.com/casbin/govaluate"
)

var _ IEnforcer = &Enforcer{}
var _ IEnforcer = &SyncedEnforcer{}
var _ IEnforcer = &CachedEnforcer{}

// IEnforcer is the API interface of Enforcer
type IEnforcer interface {
	/* Enforcer API */
	InitWithFile(modelPath string, policyPath string) error
	InitWithAdapter(modelPath string, adapter persist.Adapter) error
	InitWithModelAndAdapter(m model.Model, adapter persist.Adapter) error
	LoadModel() error
	GetModel() model.Model
	SetModel(m model.Model)
	GetAdapter() persist.Adapter
	SetAdapter(adapter persist.Adapter)
	SetWatcher(watcher persist.Watcher) error
	GetRoleManager() rbac.RoleManager
	SetRoleManager(rm rbac.RoleManager)
	SetEffector(eft effector.Effector)
	ClearPolicy()
	LoadPolicy() error
	LoadFilteredPolicy(filter interface{}) error
	LoadIncrementalFilteredPolicy(filter interface{}) error
	IsFiltered() bool
	SavePolicy() error
	EnableEnforce(enable bool)
	EnableLog(enable bool)
	EnableAutoNotifyWatcher(enable bool)
	EnableAutoSave(autoSave bool)
	EnableAutoBuildRoleLinks(autoBuildRoleLinks bool)
	BuildRoleLinks() error
	Enforce(rvals ...interface{}) (bool, error)
	EnforceWithMatcher(matcher string, rvals ...interface{}) (bool, error)
	EnforceEx(rvals ...interface{}) (bool, []string, error)
	EnforceExWithMatcher(matcher string, rvals ...interface{}) (bool, []string, error)
	BatchEnforce(requests [][]interface{}) ([]bool, error)
	BatchEnforceWithMatcher(matcher string, requests [][]interface{}) ([]bool, error)

	/* RBAC API */
	GetRolesForUser(name string, domain ...string) ([]string, error)
	GetUsersForRole(name string, domain ...string) ([]string, error)
	HasRoleForUser(name string, role string, domain ...string) (bool, error)
	AddRoleForUser(user string, role string, domain ...string) (bool, error)
	AddPermissionForUser(user string, permission ...string) (bool, error)
	AddPermissionsForUser(user string, permissions ...[]string) (bool, error)
	DeletePermissionForUser(user string, permission ...string) (bool, error)
	DeletePermissionsForUser(user string) (bool, error)
	GetPermissionsForUser(user string, domain ...string) [][]string
	HasPermissionForUser(user string, permission ...string) bool
	GetImplicitRolesForUser(name string, domain ...string) ([]string, error)
	GetImplicitPermissionsForUser(user string, domain ...string) ([][]string, error)
	GetImplicitUsersForPermission(permission ...string) ([]string, error)
	DeleteRoleForUser(user string, role string, domain ...string) (bool, error)
	DeleteRolesForUser(user string, domain ...string) (bool, error)
	DeleteUser(user string) (bool, error)
	DeleteRole(role string) (bool, error)
	DeletePermission(permission ...string) (bool, error)

	/* RBAC API with context */
	AddRoleForUserCtx(ctx context.Context, user string, role string, domain ...string) (bool, error)
	AddRolesForUserCtx(ctx context.Context, user string, roles []string, domain ...string) (bool, error)
	AddPermissionForUserCtx(ctx context.Context, user string, permission ...string) (bool, error)
	AddPermissionsForUserCtx(ctx context.Context, user string, permissions ...[]string) (bool, error)
	DeletePermissionForUserCtx(ctx context.Context, user string, permission ...string) (bool, error)
	DeletePermissionsForUserCtx(ctx context.Context, user string) (bool, error)
	DeleteRoleForUserCtx(ctx context.Context, user string, role string, domain ...string) (bool, error)
	DeleteRolesForUserCtx(ctx context.Context, user string, domain ...string) (bool, error)
	DeleteUserCtx(ctx context.Context, user string) (bool, error)
	DeleteRoleCtx(ctx context.Context, role string) (bool, error)
	DeletePermissionCtx(ctx context.Context, permission ...string) (bool, error)

	/* RBAC API with domains*/
	GetUsersForRoleInDomain(name string, domain string) []string
	GetRolesForUserInDomain(name string, domain string) []string
	GetPermissionsForUserInDomain(user string, domain string) [][]string
	AddRoleForUserInDomain(user string, role string, domain string) (bool, error)
	DeleteRoleForUserInDomain(user string, role string, domain string) (bool, error)
	GetAllUsersByDomain(domain string) []string
	DeleteRolesForUserInDomain(user string, domain string) (bool, error)
	DeleteAllUsersByDomain(domain string) (bool, error)
	DeleteDomains(domains ...string) (bool, error)
	GetAllDomains() ([]string, error)
	GetAllRolesByDomain(domain string) []string

	/* RBAC API with domains and context */
	AddRoleForUserInDomainCtx(ctx context.Context, user string, role string, domain string) (bool, error)
	DeleteRoleForUserInDomainCtx(ctx context.Context, user string, role string, domain string) (bool, error)
	DeleteRolesForUserInDomainCtx(ctx context.Context, user string, domain string) (bool, error)
	DeleteAllUsersByDomainCtx(ctx context.Context, domain string) (bool, error)
	DeleteDomainsCtx(ctx context.Context, domains ...string) (bool, error)

	/* Management API */
	GetAllSubjects() []string
	GetAllNamedSubjects(ptype string) []string
	GetAllObjects() []string
	GetAllNamedObjects(ptype string) []string
	GetAllActions() []string
	GetAllNamedActions(ptype string) []string
	GetAllRoles() []string
	GetAllNamedRoles(ptype string) []string
	GetPolicy() [][]string
	GetFilteredPolicy(fieldIndex int, fieldValues ...string) [][]string
	GetNamedPolicy(ptype string) [][]string
	GetFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) [][]string
	GetGroupingPolicy() [][]string
	GetFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) [][]string
	GetNamedGroupingPolicy(ptype string) [][]string
	GetFilteredNamedGroupingPolicy(ptype string, fieldIndex int, fieldValues ...string) [][]string
	HasPolicy(params ...interface{}) bool
	HasNamedPolicy(ptype string, params ...interface{}) bool
	AddPolicy(params ...interface{}) (bool, error)
	AddPolicies(rules [][]string) (bool, error)
	AddNamedPolicy(ptype string, params ...interface{}) (bool, error)
	AddNamedPolicies(ptype string, rules [][]string) (bool, error)
	AddPoliciesEx(rules [][]string) (bool, error)
	AddNamedPoliciesEx(ptype string, rules [][]string) (bool, error)
	RemovePolicy(params ...interface{}) (bool, error)
	RemovePolicies(rules [][]string) (bool, error)
	RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) (bool, error)
	RemoveNamedPolicy(ptype string, params ...interface{}) (bool, error)
	RemoveNamedPolicies(ptype string, rules [][]string) (bool, error)
	RemoveFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) (bool, error)
	HasGroupingPolicy(params ...interface{}) bool
	HasNamedGroupingPolicy(ptype string, params ...interface{}) bool
	AddGroupingPolicy(params ...interface{}) (bool, error)
	AddGroupingPolicies(rules [][]string) (bool, error)
	AddGroupingPoliciesEx(rules [][]string) (bool, error)
	AddNamedGroupingPolicy(ptype string, params ...interface{}) (bool, error)
	AddNamedGroupingPolicies(ptype string, rules [][]string) (bool, error)
	AddNamedGroupingPoliciesEx(ptype string, rules [][]string) (bool, error)
	RemoveGroupingPolicy(params ...interface{}) (bool, error)
	RemoveGroupingPolicies(rules [][]string) (bool, error)
	RemoveFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) (bool, error)
	RemoveNamedGroupingPolicy(ptype string, params ...interface{}) (bool, error)
	RemoveNamedGroupingPolicies(ptype string, rules [][]string) (bool, error)
	RemoveFilteredNamedGroupingPolicy(ptype string, fieldIndex int, fieldValues ...string) (bool, error)
	AddFunction(name string, function govaluate.ExpressionFunction)

	UpdatePolicy(oldPolicy []string, newPolicy []string) (bool, error)
	UpdatePolicies(oldPolicies [][]string, newPolicies [][]string) (bool, error)
	UpdateFilteredPolicies(newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error)

	UpdateGroupingPolicy(oldRule []string, newRule []string) (bool, error)
	UpdateGroupingPolicies(oldRules [][]string, newRules [][]string) (bool, error)
	UpdateNamedGroupingPolicy(ptype string, oldRule []string, newRule []string) (bool, error)
	UpdateNamedGroupingPolicies(ptype string, oldRules [][]string, newRules [][]string) (bool, error)

	/* Management API with context */
	AddPolicyCtx(ctx context.Context, params ...interface{}) (bool, error)
	AddPoliciesCtx(ctx context.Context, rules [][]string) (bool, error)
	AddNamedPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error)
	AddNamedPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error)
	AddPoliciesExCtx(ctx context.Context, rules [][]string) (bool, error)
	AddNamedPoliciesExCtx(ctx context.Context, ptype string, rules [][]string) (bool, error)
	RemovePolicyCtx(ctx context.Context, params ...interface{}) (bool, error)
	RemovePoliciesCtx(ctx context.Context, rules [][]string) (bool, error)
	RemoveFilteredPolicyCtx(ctx context.Context, fieldIndex int, fieldValues ...string) (bool, error)
	RemoveNamedPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error)
	RemoveNamedPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error)
	RemoveFilteredNamedPolicyCtx(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) (bool, error)
	AddGroupingPolicyCtx(ctx context.Context, params ...interface{}) (bool, error)
	AddGroupingPoliciesCtx(ctx context.Context, rules [][]string) (bool, error)
	AddGroupingPoliciesExCtx(ctx context.Context, rules [][]string) (bool, error)
	AddNamedGroupingPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error)
	AddNamedGroupingPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error)
	AddNamedGroupingPoliciesExCtx(ctx context.Context, ptype string, rules [][]string) (bool, error)
	RemoveGroupingPolicyCtx(ctx context.Context, params ...interface{}) (bool, error)
	RemoveGroupingPoliciesCtx(ctx context.Context, rules [][]string) (bool, error)
	RemoveFilteredGroupingPolicyCtx(ctx context.Context, fieldIndex int, fieldValues ...string) (bool, error)
	RemoveNamedGroupingPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error)
	RemoveNamedGroupingPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error)
	RemoveFilteredNamedGroupingPolicyCtx(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) (bool, error)
	UpdatePolicyCtx(ctx context.Context, oldPolicy []string, newPolicy []string) (bool, error)
	UpdatePoliciesCtx(ctx context.Context, oldPolicies [][]string, newPolicies [][]string) (bool, error)
	UpdateFilteredPoliciesCtx(ctx context.Context, newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error)
	UpdateGroupingPolicyCtx(ctx context.Context, oldRule []string, newRule []string) (bool, error)
	UpdateGroupingPoliciesCtx(ctx context.Context, oldRules [][]string, newRules [][]string) (bool, error)
	UpdateNamedGroupingPolicyCtx(ctx context.Context, ptype string, oldRule []string, newRule []string) (bool, error)
	UpdateNamedGroupingPoliciesCtx(ctx context.Context, ptype string, oldRules [][]string, newRules [][]string) (bool, error)

	/* Management API with autoNotifyWatcher disabled */
	SelfAddPolicy(sec string, ptype string, rule []string) (bool, error)
	SelfAddPolicies(sec string, ptype string, rules [][]string) (bool, error)
	SelfAddPoliciesEx(sec string, ptype string, rules [][]string) (bool, error)
	SelfRemovePolicy(sec string, ptype string, rule []string) (bool, error)
	SelfRemovePolicies(sec string, ptype string, rules [][]string) (bool, error)
	SelfRemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, error)
	SelfUpdatePolicy(sec string, ptype string, oldRule, newRule []string) (bool, error)
	SelfUpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) (bool, error)

	/* Management API with autoNotifyWatcher disabled, without adapter */
	SelfAddPolicyModel(sec string, ptype string, rule []string) (bool, error)
	SelfAddPoliciesModel(sec string, ptype string, rules [][]string) (bool, error)
	SelfAddPoliciesExModel(sec string, ptype string, rules [][]string) (bool, error)
	SelfRemovePolicyModel(sec string, ptype string, rule []string) (bool, error)
	SelfRemovePoliciesModel(sec string, ptype string, rules [][]string) (bool, error)
	SelfRemoveFilteredPolicyModel(sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, error)
	SelfUpdatePolicyModel(sec string, ptype string, oldRule, newRule []string) (bool, error)
	SelfUpdatePoliciesModel(sec string, ptype string, oldRules, newRules [][]string) (bool, error)
}

var _ IDistributedEnforcer = &DistributedEnforcer{}

// IDistributedEnforcer defines dispatcher enforcer.
type IDistributedEnforcer interface {
	IEnforcer
	SetDispatcher(dispatcher persist.Dispatcher)
	/* Management API for DistributedEnforcer*/
	AddPoliciesSelf(shouldPersist func() bool, sec string, ptype string, rules [][]string) (affected [][]string, err error)
	RemovePoliciesSelf(shouldPersist func() bool, sec string, ptype string, rules [][]string) (affected [][]string, err error)
	RemoveFilteredPolicySelf(shouldPersist func() bool, sec string, ptype string, fieldIndex int, fieldValues ...string) (affected [][]string, err error)
	ClearPolicySelf(shouldPersist func() bool) error
	UpdatePolicySelf(shouldPersist func() bool, sec string, ptype string, oldRule, newRule []string) (affected bool, err error)
	UpdatePoliciesSelf(shouldPersist func() bool, sec string, ptype string, oldRules, newRules [][]string) (affected bool, err error)
	UpdateFilteredPoliciesSelf(shouldPersist func() bool, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) (bool, error)
}

var _ ISyncedContextEnforcer = &SyncedContextEnforcer{}

// ISyncedContextEnforcer defines dispatcher enforcer.
type ISyncedContextEnforcer interface {
	IEnforcer
	LoadPolicySyncWatcher() error
	LoadPolicyCtx(ctx context.Context) error
	LoadPolicyFastCtx(ctx context.Context) error
	LoadFilteredPolicyCtx(ctx context.Context, filter interface{}) error
	LoadIncrementalFilteredPolicyCtx(ctx context.Context, filter interface{}) error
	SavePolicyCtx(ctx context.Context) error
}
