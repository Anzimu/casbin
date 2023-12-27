package casbin

import (
	"context"
	"fmt"
	Err "github.com/anzimu/casbin/v2/errors"
	"github.com/anzimu/casbin/v2/model"
	"github.com/anzimu/casbin/v2/persist"
)

// addPolicyWithoutNotifyCtx adds a rule to the current policy.
func (e *Enforcer) addPolicyWithoutNotifyCtx(ctx context.Context, sec string, ptype string, rule []string) (bool, error) {
	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.AddPolicies(sec, ptype, [][]string{rule})
	}

	if e.model.HasPolicy(sec, ptype, rule) {
		return false, nil
	}

	if e.shouldPersist() {
		if err := e.adapter.(persist.ContextAdapter).AddPolicyCtx(ctx, sec, ptype, rule); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	e.model.AddPolicy(sec, ptype, rule)

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, [][]string{rule})
		if err != nil {
			return true, err
		}
	}

	return true, nil
}

// addPoliciesWithoutNotifyCtx adds rules to the current policy without notify
// If autoRemoveRepeat == true, existing rules are automatically filtered
// Otherwise, false is returned directly
func (e *Enforcer) addPoliciesWithoutNotifyCtx(ctx context.Context, sec string, ptype string, rules [][]string, autoRemoveRepeat bool) (bool, error) {
	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.AddPolicies(sec, ptype, rules)
	}

	if !autoRemoveRepeat && e.model.HasPolicies(sec, ptype, rules) {
		return false, nil
	}

	if e.shouldPersist() {
		if err := e.adapter.(persist.BatchContextAdapter).AddPoliciesCtx(ctx, sec, ptype, rules); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	e.model.AddPolicies(sec, ptype, rules)

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, rules)
		if err != nil {
			return true, err
		}

		err = e.BuildIncrementalConditionalRoleLinks(model.PolicyAdd, ptype, rules)
		if err != nil {
			return true, err
		}
	}

	return true, nil
}

// removePolicyWithoutNotifyCtx removes a rule from the current policy.
func (e *Enforcer) removePolicyWithoutNotifyCtx(ctx context.Context, sec string, ptype string, rule []string) (bool, error) {
	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.RemovePolicies(sec, ptype, [][]string{rule})
	}

	if e.shouldPersist() {
		if err := e.adapter.(persist.ContextAdapter).RemovePolicyCtx(ctx, sec, ptype, rule); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	ruleRemoved := e.model.RemovePolicy(sec, ptype, rule)
	if !ruleRemoved {
		return ruleRemoved, nil
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, [][]string{rule})
		if err != nil {
			return ruleRemoved, err
		}
	}

	return ruleRemoved, nil
}

func (e *Enforcer) updatePolicyWithoutNotifyCtx(ctx context.Context, sec string, ptype string, oldRule []string, newRule []string) (bool, error) {
	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.UpdatePolicy(sec, ptype, oldRule, newRule)
	}

	if e.shouldPersist() {
		if err := e.adapter.(persist.UpdatableContextAdapter).UpdatePolicyCtx(ctx, sec, ptype, oldRule, newRule); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}
	ruleUpdated := e.model.UpdatePolicy(sec, ptype, oldRule, newRule)
	if !ruleUpdated {
		return ruleUpdated, nil
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, [][]string{oldRule}) // remove the old rule
		if err != nil {
			return ruleUpdated, err
		}
		err = e.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, [][]string{newRule}) // add the new rule
		if err != nil {
			return ruleUpdated, err
		}
	}

	return ruleUpdated, nil
}

func (e *Enforcer) updatePoliciesWithoutNotifyCtx(ctx context.Context, sec string, ptype string, oldRules [][]string, newRules [][]string) (bool, error) {
	if len(newRules) != len(oldRules) {
		return false, fmt.Errorf("the length of oldRules should be equal to the length of newRules, but got the length of oldRules is %d, the length of newRules is %d", len(oldRules), len(newRules))
	}

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.UpdatePolicies(sec, ptype, oldRules, newRules)
	}

	if e.shouldPersist() {
		if err := e.adapter.(persist.UpdatableContextAdapter).UpdatePoliciesCtx(ctx, sec, ptype, oldRules, newRules); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	ruleUpdated := e.model.UpdatePolicies(sec, ptype, oldRules, newRules)
	if !ruleUpdated {
		return ruleUpdated, nil
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, oldRules) // remove the old rules
		if err != nil {
			return ruleUpdated, err
		}
		err = e.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, newRules) // add the new rules
		if err != nil {
			return ruleUpdated, err
		}
	}

	return ruleUpdated, nil
}

// removePolicies removes rules from the current policy.
func (e *Enforcer) removePoliciesWithoutNotifyCtx(ctx context.Context, sec string, ptype string, rules [][]string) (bool, error) {
	if !e.model.HasPolicies(sec, ptype, rules) {
		return false, nil
	}

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.RemovePolicies(sec, ptype, rules)
	}

	if e.shouldPersist() {
		if err := e.adapter.(persist.BatchContextAdapter).RemovePoliciesCtx(ctx, sec, ptype, rules); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	rulesRemoved := e.model.RemovePolicies(sec, ptype, rules)
	if !rulesRemoved {
		return rulesRemoved, nil
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, rules)
		if err != nil {
			return rulesRemoved, err
		}
	}
	return rulesRemoved, nil
}

// removeFilteredPolicy removes rules based on field filters from the current policy.
func (e *Enforcer) removeFilteredPolicyWithoutNotifyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues []string) (bool, error) {
	if len(fieldValues) == 0 {
		return false, Err.ErrInvalidFieldValuesParameter
	}

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	}

	if e.shouldPersist() {
		if err := e.adapter.(persist.ContextAdapter).RemoveFilteredPolicyCtx(ctx, sec, ptype, fieldIndex, fieldValues...); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	ruleRemoved, effects := e.model.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	if !ruleRemoved {
		return ruleRemoved, nil
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, effects)
		if err != nil {
			return ruleRemoved, err
		}
	}

	return ruleRemoved, nil
}

func (e *Enforcer) updateFilteredPoliciesWithoutNotifyCtx(ctx context.Context, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	var (
		oldRules [][]string
		err      error
	)

	if e.shouldPersist() {
		if oldRules, err = e.adapter.(persist.UpdatableContextAdapter).UpdateFilteredPoliciesCtx(ctx, sec, ptype, newRules, fieldIndex, fieldValues...); err != nil {
			if err.Error() != notImplemented {
				return nil, err
			}
		}
		// For compatibility, because some adapters return oldRules containing ptype, see https://github.com/casbin/xorm-adapter/issues/49
		for i, oldRule := range oldRules {
			if len(oldRules[i]) == len(e.model[sec][ptype].Tokens)+1 {
				oldRules[i] = oldRule[1:]
			}
		}
	}

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return oldRules, e.dispatcher.UpdateFilteredPolicies(sec, ptype, oldRules, newRules)
	}

	ruleChanged := e.model.RemovePolicies(sec, ptype, oldRules)
	e.model.AddPolicies(sec, ptype, newRules)
	ruleChanged = ruleChanged && len(newRules) != 0
	if !ruleChanged {
		return make([][]string, 0), nil
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, oldRules) // remove the old rules
		if err != nil {
			return oldRules, err
		}
		err = e.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, newRules) // add the new rules
		if err != nil {
			return oldRules, err
		}
	}

	return oldRules, nil
}

// addPolicyCtx adds a rule to the current policy.
func (e *Enforcer) addPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) (bool, error) {
	ok, err := e.addPolicyWithoutNotifyCtx(ctx, sec, ptype, rule)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForAddPolicy(sec, ptype, rule...)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

// addPoliciesCtx adds rules to the current policy.
// If autoRemoveRepeat == true, existing rules are automatically filtered
// Otherwise, false is returned directly
func (e *Enforcer) addPoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string, autoRemoveRepeat bool) (bool, error) {
	ok, err := e.addPoliciesWithoutNotifyCtx(ctx, sec, ptype, rules, autoRemoveRepeat)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForAddPolicies(sec, ptype, rules...)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

// removePolicyCtx removes a rule from the current policy.
func (e *Enforcer) removePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) (bool, error) {
	ok, err := e.removePolicyWithoutNotifyCtx(ctx, sec, ptype, rule)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForRemovePolicy(sec, ptype, rule...)
		} else {
			err = e.watcher.Update()
		}
		return true, err

	}

	return true, nil
}

func (e *Enforcer) updatePolicyCtx(ctx context.Context, sec string, ptype string, oldRule []string, newRule []string) (bool, error) {
	ok, err := e.updatePolicyWithoutNotifyCtx(ctx, sec, ptype, oldRule, newRule)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.UpdatableWatcher); ok {
			err = watcher.UpdateForUpdatePolicy(sec, ptype, oldRule, newRule)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

func (e *Enforcer) updatePoliciesCtx(ctx context.Context, sec string, ptype string, oldRules [][]string, newRules [][]string) (bool, error) {
	ok, err := e.updatePoliciesWithoutNotifyCtx(ctx, sec, ptype, oldRules, newRules)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.UpdatableWatcher); ok {
			err = watcher.UpdateForUpdatePolicies(sec, ptype, oldRules, newRules)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

// removePoliciesCtx removes rules from the current policy.
func (e *Enforcer) removePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) (bool, error) {
	ok, err := e.removePoliciesWithoutNotifyCtx(ctx, sec, ptype, rules)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForRemovePolicies(sec, ptype, rules...)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

// removeFilteredPolicyCtx removes rules based on field filters from the current policy.
func (e *Enforcer) removeFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues []string) (bool, error) {
	ok, err := e.removeFilteredPolicyWithoutNotifyCtx(ctx, sec, ptype, fieldIndex, fieldValues)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForRemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

func (e *Enforcer) updateFilteredPoliciesCtx(ctx context.Context, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	oldRules, err := e.updateFilteredPoliciesWithoutNotifyCtx(ctx, sec, ptype, newRules, fieldIndex, fieldValues...)
	ok := len(oldRules) != 0
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.UpdatableWatcher); ok {
			err = watcher.UpdateForUpdatePolicies(sec, ptype, oldRules, newRules)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}
