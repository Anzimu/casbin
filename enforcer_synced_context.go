package casbin

import (
	"context"
	"errors"
	"github.com/anzimu/casbin/v2/persist"
	"github.com/anzimu/casbin/v2/rbac"
	defaultrolemanager "github.com/anzimu/casbin/v2/rbac/default-role-manager"
)

// SyncedContextEnforcer  wraps Enforcer and provides synchronized access, and functions with context
type SyncedContextEnforcer struct {
	*SyncedEnforcer
}

// NewSyncedContextEnforcer creates a synchronized enforcer handler via file or DB.
func NewSyncedContextEnforcer(params ...interface{}) (*SyncedContextEnforcer, error) {
	e := &SyncedContextEnforcer{SyncedEnforcer: &SyncedEnforcer{}}
	enforcer, err := NewEnforcer(params...)
	if err != nil {
		return nil, err
	}

	e.Enforcer = enforcer
	e.stopAutoLoad = make(chan struct{}, 1)
	e.autoLoadRunning = 0
	return e, nil
}

// LoadPolicySyncWatcher reloads the policy from file/database and notify to watcher.
func (e *SyncedContextEnforcer) LoadPolicySyncWatcher() error {
	e.m.Lock()
	defer e.m.Unlock()

	if err := e.Enforcer.LoadPolicy(); err != nil {
		return err
	}

	if err := e.watcher.Update(); err != nil {
		return err
	}

	return nil
}

// LoadPolicyCtx reloads the policy from file/database.
func (e *SyncedContextEnforcer) LoadPolicyCtx(ctx context.Context) error {
	e.m.Lock()
	defer e.m.Unlock()

	e.invalidateMatcherMap()

	needToRebuild := false
	newModel := e.model.Copy()
	newModel.ClearPolicy()

	var err error
	defer func() {
		if err != nil {
			if e.autoBuildRoleLinks && needToRebuild {
				_ = e.BuildRoleLinks()
			}
		}
	}()

	if adapter, ok := e.adapter.(persist.ContextAdapter); ok {
		if err = adapter.LoadPolicyCtx(ctx, newModel); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
			return err
		}
	} else {
		return errors.New("context are not supported by this adapter")
	}

	if err = newModel.SortPoliciesBySubjectHierarchy(); err != nil {
		return err
	}

	if err = newModel.SortPoliciesByPriority(); err != nil {
		return err
	}

	if e.autoBuildRoleLinks {
		needToRebuild = true
		if err := e.rebuildRoleLinks(newModel); err != nil {
			return err
		}

		if err := e.rebuildConditionalRoleLinks(newModel); err != nil {
			return err
		}
	}
	e.model = newModel
	return nil
}

// LoadPolicyFastCtx is not blocked when adapter calls LoadPolicy.
func (e *SyncedContextEnforcer) LoadPolicyFastCtx(ctx context.Context) error {
	e.m.RLock()
	newModel := e.model.Copy()
	e.m.RUnlock()

	newModel.ClearPolicy()
	newRmMap := map[string]rbac.RoleManager{}
	var err error

	if err = e.adapter.(persist.ContextAdapter).LoadPolicyCtx(ctx, newModel); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
		return err
	}

	if err = newModel.SortPoliciesBySubjectHierarchy(); err != nil {
		return err
	}

	if err = newModel.SortPoliciesByPriority(); err != nil {
		return err
	}

	if e.autoBuildRoleLinks {
		for ptype := range newModel["g"] {
			newRmMap[ptype] = defaultrolemanager.NewRoleManager(10)
		}
		err = newModel.BuildRoleLinks(newRmMap)
		if err != nil {
			return err
		}
	}

	// reduce the lock range
	e.m.Lock()
	defer e.m.Unlock()
	e.model = newModel
	e.rmMap = newRmMap
	return nil
}

func (e *SyncedContextEnforcer) loadFilteredPolicyCtx(ctx context.Context, filter interface{}) error {
	e.invalidateMatcherMap()

	var filteredContextAdapter persist.FilteredContextAdapter

	// Attempt to cast the Adapter as a FilteredAdapter
	switch adapter := e.adapter.(type) {
	case persist.FilteredContextAdapter:
		filteredContextAdapter = adapter
	default:
		return errors.New("filtered policies are not supported by this adapter")
	}
	if err := filteredContextAdapter.LoadFilteredPolicyCtx(ctx, e.model, filter); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
		return err
	}

	if err := e.model.SortPoliciesBySubjectHierarchy(); err != nil {
		return err
	}

	if err := e.model.SortPoliciesByPriority(); err != nil {
		return err
	}

	e.initRmMap()
	e.model.PrintPolicy()
	if e.autoBuildRoleLinks {
		err := e.BuildRoleLinks()
		if err != nil {
			return err
		}
	}
	return nil
}

// LoadFilteredPolicyCtx reloads a filtered policy from file/database.
func (e *SyncedContextEnforcer) LoadFilteredPolicyCtx(ctx context.Context, filter interface{}) error {
	e.m.Lock()
	defer e.m.Unlock()
	e.model.ClearPolicy()

	return e.loadFilteredPolicyCtx(ctx, filter)
}

// LoadIncrementalFilteredPolicyCtx reloads a filtered policy from file/database.
func (e *SyncedContextEnforcer) LoadIncrementalFilteredPolicyCtx(ctx context.Context, filter interface{}) error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.loadFilteredPolicyCtx(ctx, filter)
}

// SavePolicyCtx saves the current policy (usually after changed with Casbin API) back to file/database.
func (e *SyncedContextEnforcer) SavePolicyCtx(ctx context.Context) error {
	e.m.Lock()
	defer e.m.Unlock()

	if e.IsFiltered() {
		return errors.New("cannot save a filtered policy")
	}
	if adapter, ok := e.adapter.(persist.ContextAdapter); ok {
		if err := adapter.SavePolicyCtx(ctx, e.model); err != nil {
			return err
		}
	} else {
		return errors.New("context are not supported by this adapter")
	}
	if e.watcher != nil {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForSavePolicy(e.model)
		} else {
			err = e.watcher.Update()
		}
		return err
	}
	return nil
}

// AddPolicyCtx adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *SyncedContextEnforcer) AddPolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddPolicyCtx(ctx, params...)
}

// AddPoliciesCtx adds authorization rules to the current policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding rule by adding the new rule.
func (e *SyncedContextEnforcer) AddPoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddPoliciesCtx(ctx, rules)
}

// AddPoliciesExCtx adds authorization rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddPolicies, other non-existent rules are added instead of returning false directly
func (e *SyncedContextEnforcer) AddPoliciesExCtx(ctx context.Context, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddPoliciesExCtx(ctx, rules)
}

// AddNamedPolicyCtx adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *SyncedContextEnforcer) AddNamedPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedPolicyCtx(ctx, ptype, params...)
}

// AddNamedPoliciesCtx adds authorization rules to the current named policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding by adding the new rule.
func (e *SyncedContextEnforcer) AddNamedPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedPoliciesCtx(ctx, ptype, rules)
}

// AddNamedPoliciesExCtx adds authorization rules to the current named policy.
// If the rule already exists, the rule will not be added.
// But unlike AddNamedPolicies, other non-existent rules are added instead of returning false directly
func (e *SyncedContextEnforcer) AddNamedPoliciesExCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedPoliciesExCtx(ctx, ptype, rules)
}

// RemovePolicyCtx removes an authorization rule from the current policy.
func (e *SyncedContextEnforcer) RemovePolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemovePolicyCtx(ctx, params...)
}

// UpdatePolicyCtx updates an authorization rule from the current policy.
func (e *SyncedContextEnforcer) UpdatePolicyCtx(ctx context.Context, oldPolicy []string, newPolicy []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdatePolicyCtx(ctx, oldPolicy, newPolicy)
}

func (e *SyncedContextEnforcer) UpdateNamedPolicyCtx(ctx context.Context, ptype string, p1 []string, p2 []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedPolicyCtx(ctx, ptype, p1, p2)
}

// UpdatePoliciesCtx updates authorization rules from the current policies.
func (e *SyncedContextEnforcer) UpdatePoliciesCtx(ctx context.Context, oldPolices [][]string, newPolicies [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdatePoliciesCtx(ctx, oldPolices, newPolicies)
}

func (e *SyncedContextEnforcer) UpdateNamedPoliciesCtx(ctx context.Context, ptype string, p1 [][]string, p2 [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedPoliciesCtx(ctx, ptype, p1, p2)
}

func (e *SyncedContextEnforcer) UpdateFilteredPoliciesCtx(ctx context.Context, newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateFilteredPoliciesCtx(ctx, newPolicies, fieldIndex, fieldValues...)
}

func (e *SyncedContextEnforcer) UpdateFilteredNamedPoliciesCtx(ctx context.Context, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateFilteredNamedPoliciesCtx(ctx, ptype, newPolicies, fieldIndex, fieldValues...)
}

// RemovePoliciesCtx removes authorization rules from the current policy.
func (e *SyncedContextEnforcer) RemovePoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemovePoliciesCtx(ctx, rules)
}

// RemoveFilteredPolicyCtx removes an authorization rule from the current policy, field filters can be specified.
func (e *SyncedContextEnforcer) RemoveFilteredPolicyCtx(ctx context.Context, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredPolicyCtx(ctx, fieldIndex, fieldValues...)
}

// RemoveNamedPolicyCtx removes an authorization rule from the current named policy.
func (e *SyncedContextEnforcer) RemoveNamedPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedPolicyCtx(ctx, ptype, params...)
}

// RemoveNamedPoliciesCtx removes authorization rules from the current named policy.
func (e *SyncedContextEnforcer) RemoveNamedPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedPoliciesCtx(ctx, ptype, rules)
}

// RemoveFilteredNamedPolicyCtx removes an authorization rule from the current named policy, field filters can be specified.
func (e *SyncedContextEnforcer) RemoveFilteredNamedPolicyCtx(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredNamedPolicyCtx(ctx, ptype, fieldIndex, fieldValues...)
}

// AddGroupingPolicyCtx adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *SyncedContextEnforcer) AddGroupingPolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddGroupingPolicyCtx(ctx, params...)
}

// AddGroupingPoliciesCtx adds role inheritance rulea to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
func (e *SyncedContextEnforcer) AddGroupingPoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddGroupingPoliciesCtx(ctx, rules)
}

// AddGroupingPoliciesExCtx adds role inheritance rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddGroupingPoliciesCtx, other non-existent rules are added instead of returning false directly
func (e *SyncedContextEnforcer) AddGroupingPoliciesExCtx(ctx context.Context, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddGroupingPoliciesExCtx(ctx, rules)
}

// AddNamedGroupingPolicyCtx adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *SyncedContextEnforcer) AddNamedGroupingPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedGroupingPolicyCtx(ctx, ptype, params...)
}

// AddNamedGroupingPoliciesCtx adds named role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
func (e *SyncedContextEnforcer) AddNamedGroupingPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedGroupingPoliciesCtx(ctx, ptype, rules)
}

// AddNamedGroupingPoliciesExCtx adds named role inheritance rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddNamedGroupingPoliciesCtx, other non-existent rules are added instead of returning false directly
func (e *SyncedContextEnforcer) AddNamedGroupingPoliciesExCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedGroupingPoliciesExCtx(ctx, ptype, rules)
}

// RemoveGroupingPolicyCtx removes a role inheritance rule from the current policy.
func (e *SyncedContextEnforcer) RemoveGroupingPolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveGroupingPolicyCtx(ctx, params...)
}

// RemoveGroupingPoliciesCtx removes role inheritance rules from the current policy.
func (e *SyncedContextEnforcer) RemoveGroupingPoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveGroupingPoliciesCtx(ctx, rules)
}

// RemoveFilteredGroupingPolicyCtx removes a role inheritance rule from the current policy, field filters can be specified.
func (e *SyncedContextEnforcer) RemoveFilteredGroupingPolicyCtx(ctx context.Context, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredGroupingPolicyCtx(ctx, fieldIndex, fieldValues...)
}

// RemoveNamedGroupingPolicyCtx removes a role inheritance rule from the current named policy.
func (e *SyncedContextEnforcer) RemoveNamedGroupingPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedGroupingPolicyCtx(ctx, ptype, params...)
}

// RemoveNamedGroupingPoliciesCtx removes role inheritance rules from the current named policy.
func (e *SyncedContextEnforcer) RemoveNamedGroupingPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedGroupingPoliciesCtx(ctx, ptype, rules)
}

func (e *SyncedContextEnforcer) UpdateGroupingPolicyCtx(ctx context.Context, oldRule []string, newRule []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateGroupingPolicyCtx(ctx, oldRule, newRule)
}

func (e *SyncedContextEnforcer) UpdateGroupingPoliciesCtx(ctx context.Context, oldRules [][]string, newRules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateGroupingPoliciesCtx(ctx, oldRules, newRules)
}

func (e *SyncedContextEnforcer) UpdateNamedGroupingPolicyCtx(ctx context.Context, ptype string, oldRule []string, newRule []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedGroupingPolicyCtx(ctx, ptype, oldRule, newRule)
}

func (e *SyncedContextEnforcer) UpdateNamedGroupingPoliciesCtx(ctx context.Context, ptype string, oldRules [][]string, newRules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedGroupingPoliciesCtx(ctx, ptype, oldRules, newRules)
}

// RemoveFilteredNamedGroupingPolicyCtx removes a role inheritance rule from the current named policy, field filters can be specified.
func (e *SyncedContextEnforcer) RemoveFilteredNamedGroupingPolicyCtx(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredNamedGroupingPolicyCtx(ctx, ptype, fieldIndex, fieldValues...)
}
