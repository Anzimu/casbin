package casbin

import "context"

// AddPolicyCtx adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddPolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	return e.AddNamedPolicyCtx(ctx, "p", params...)
}

// AddPoliciesCtx adds authorization rules to the current policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding rule by adding the new rule.
func (e *Enforcer) AddPoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.AddNamedPoliciesCtx(ctx, "p", rules)
}

// AddPoliciesExCtx adds authorization rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddPolicies, other non-existent rules are added instead of returning false directly
func (e *Enforcer) AddPoliciesExCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.AddNamedPoliciesExCtx(ctx, "p", rules)
}

// AddNamedPolicyCtx adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddNamedPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		strSlice = append(make([]string, 0, len(strSlice)), strSlice...)
		return e.addPolicyCtx(ctx, "p", ptype, strSlice)
	}
	policy := make([]string, 0)
	for _, param := range params {
		policy = append(policy, param.(string))
	}

	return e.addPolicyCtx(ctx, "p", ptype, policy)
}

// AddNamedPoliciesCtx adds authorization rules to the current named policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding by adding the new rule.
func (e *Enforcer) AddNamedPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesCtx(ctx, "p", ptype, rules, false)
}

// AddNamedPoliciesExCtx adds authorization rules to the current named policy.
// If the rule already exists, the rule will not be added.
// But unlike AddNamedPolicies, other non-existent rules are added instead of returning false directly
func (e *Enforcer) AddNamedPoliciesExCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesCtx(ctx, "p", ptype, rules, true)
}

// RemovePolicyCtx removes an authorization rule from the current policy.
func (e *Enforcer) RemovePolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	return e.RemoveNamedPolicyCtx(ctx, "p", params...)
}

// UpdatePolicyCtx updates an authorization rule from the current policy.
func (e *Enforcer) UpdatePolicyCtx(ctx context.Context, oldPolicy []string, newPolicy []string) (bool, error) {
	return e.UpdateNamedPolicyCtx(ctx, "p", oldPolicy, newPolicy)
}

func (e *Enforcer) UpdateNamedPolicyCtx(ctx context.Context, ptype string, p1 []string, p2 []string) (bool, error) {
	return e.updatePolicyCtx(ctx, "p", ptype, p1, p2)
}

// UpdatePoliciesCtx updates authorization rules from the current policies.
func (e *Enforcer) UpdatePoliciesCtx(ctx context.Context, oldPolices [][]string, newPolicies [][]string) (bool, error) {
	return e.UpdateNamedPoliciesCtx(ctx, "p", oldPolices, newPolicies)
}

func (e *Enforcer) UpdateNamedPoliciesCtx(ctx context.Context, ptype string, p1 [][]string, p2 [][]string) (bool, error) {
	return e.updatePoliciesCtx(ctx, "p", ptype, p1, p2)
}

func (e *Enforcer) UpdateFilteredPoliciesCtx(ctx context.Context, newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.UpdateFilteredNamedPoliciesCtx(ctx, "p", newPolicies, fieldIndex, fieldValues...)
}

func (e *Enforcer) UpdateFilteredNamedPoliciesCtx(ctx context.Context, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.updateFilteredPoliciesCtx(ctx, "p", ptype, newPolicies, fieldIndex, fieldValues...)
}

// RemovePoliciesCtx removes authorization rules from the current policy.
func (e *Enforcer) RemovePoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.RemoveNamedPoliciesCtx(ctx, "p", rules)
}

// RemoveFilteredPolicyCtx removes an authorization rule from the current policy, field filters can be specified.
func (e *Enforcer) RemoveFilteredPolicyCtx(ctx context.Context, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.RemoveFilteredNamedPolicyCtx(ctx, "p", fieldIndex, fieldValues...)
}

// RemoveNamedPolicyCtx removes an authorization rule from the current named policy.
func (e *Enforcer) RemoveNamedPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		return e.removePolicy("p", ptype, strSlice)
	}
	policy := make([]string, 0)
	for _, param := range params {
		policy = append(policy, param.(string))
	}

	return e.removePolicyCtx(ctx, "p", ptype, policy)
}

// RemoveNamedPoliciesCtx removes authorization rules from the current named policy.
func (e *Enforcer) RemoveNamedPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.removePoliciesCtx(ctx, "p", ptype, rules)
}

// RemoveFilteredNamedPolicyCtx removes an authorization rule from the current named policy, field filters can be specified.
func (e *Enforcer) RemoveFilteredNamedPolicyCtx(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.removeFilteredPolicyCtx(ctx, "p", ptype, fieldIndex, fieldValues)
}

// AddGroupingPolicyCtx adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddGroupingPolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	return e.AddNamedGroupingPolicyCtx(ctx, "g", params...)
}

// AddGroupingPoliciesCtx adds role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
func (e *Enforcer) AddGroupingPoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.AddNamedGroupingPoliciesCtx(ctx, "g", rules)
}

// AddGroupingPoliciesExCtx adds role inheritance rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddGroupingPoliciesCtx, other non-existent rules are added instead of returning false directly
func (e *Enforcer) AddGroupingPoliciesExCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.AddNamedGroupingPoliciesExCtx(ctx, "g", rules)
}

// AddNamedGroupingPolicyCtx adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddNamedGroupingPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	var ruleAdded bool
	var err error
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		ruleAdded, err = e.addPolicyCtx(ctx, "g", ptype, strSlice)
	} else {
		policy := make([]string, 0)
		for _, param := range params {
			policy = append(policy, param.(string))
		}

		ruleAdded, err = e.addPolicyCtx(ctx, "g", ptype, policy)
	}

	return ruleAdded, err
}

// AddNamedGroupingPoliciesCtx adds named role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
func (e *Enforcer) AddNamedGroupingPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesCtx(ctx, "g", ptype, rules, false)
}

// AddNamedGroupingPoliciesExCtx adds named role inheritance rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddNamedGroupingPoliciesCtx, other non-existent rules are added instead of returning false directly
func (e *Enforcer) AddNamedGroupingPoliciesExCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesCtx(ctx, "g", ptype, rules, true)
}

// RemoveGroupingPolicyCtx removes a role inheritance rule from the current policy.
func (e *Enforcer) RemoveGroupingPolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	return e.RemoveNamedGroupingPolicyCtx(ctx, "g", params...)
}

// RemoveGroupingPoliciesCtx removes role inheritance rules from the current policy.
func (e *Enforcer) RemoveGroupingPoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.RemoveNamedGroupingPoliciesCtx(ctx, "g", rules)
}

// RemoveFilteredGroupingPolicyCtx removes a role inheritance rule from the current policy, field filters can be specified.
func (e *Enforcer) RemoveFilteredGroupingPolicyCtx(ctx context.Context, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.RemoveFilteredNamedGroupingPolicyCtx(ctx, "g", fieldIndex, fieldValues...)
}

// RemoveNamedGroupingPolicyCtx removes a role inheritance rule from the current named policy.
func (e *Enforcer) RemoveNamedGroupingPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	var ruleRemoved bool
	var err error
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		ruleRemoved, err = e.removePolicyCtx(ctx, "g", ptype, strSlice)
	} else {
		policy := make([]string, 0)
		for _, param := range params {
			policy = append(policy, param.(string))
		}

		ruleRemoved, err = e.removePolicyCtx(ctx, "g", ptype, policy)
	}

	return ruleRemoved, err
}

// RemoveNamedGroupingPoliciesCtx removes role inheritance rules from the current named policy.
func (e *Enforcer) RemoveNamedGroupingPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.removePoliciesCtx(ctx, "g", ptype, rules)
}

func (e *Enforcer) UpdateGroupingPolicyCtx(ctx context.Context, oldRule []string, newRule []string) (bool, error) {
	return e.UpdateNamedGroupingPolicyCtx(ctx, "g", oldRule, newRule)
}

// UpdateGroupingPoliciesCtx updates authorization rules from the current policies.
func (e *Enforcer) UpdateGroupingPoliciesCtx(ctx context.Context, oldRules [][]string, newRules [][]string) (bool, error) {
	return e.UpdateNamedGroupingPoliciesCtx(ctx, "g", oldRules, newRules)
}

func (e *Enforcer) UpdateNamedGroupingPolicyCtx(ctx context.Context, ptype string, oldRule []string, newRule []string) (bool, error) {
	return e.updatePolicyCtx(ctx, "g", ptype, oldRule, newRule)
}

func (e *Enforcer) UpdateNamedGroupingPoliciesCtx(ctx context.Context, ptype string, oldRules [][]string, newRules [][]string) (bool, error) {
	return e.updatePoliciesCtx(ctx, "g", ptype, oldRules, newRules)
}

// RemoveFilteredNamedGroupingPolicyCtx removes a role inheritance rule from the current named policy, field filters can be specified.
func (e *Enforcer) RemoveFilteredNamedGroupingPolicyCtx(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.removeFilteredPolicyCtx(ctx, "g", ptype, fieldIndex, fieldValues)
}
