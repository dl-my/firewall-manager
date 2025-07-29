package firewall

import (
	"context"
	"encoding/json"
	"firewall-manager/common/logs"
	"firewall-manager/common/utils"
	"firewall-manager/model"
	"fmt"
	"go.uber.org/zap"
	"os"
	"sync"
)

type RuleGetter interface {
	GetRule() model.Rule
}

// 通用缓存结构体
type RuleCache[T RuleGetter] struct {
	cache map[int][]T
	index map[string]struct{}
	sync.RWMutex
}

func NewRuleCache[T RuleGetter]() *RuleCache[T] {
	return &RuleCache[T]{
		cache: make(map[int][]T),
		index: make(map[string]struct{}),
	}
}

// TODO action/chain 大小写不同合并ip
func (r *RuleCache[T]) Add(rule T, key string) {
	r.Lock()
	defer r.Unlock()
	port := rule.GetRule().Port
	r.cache[port] = append(r.cache[port], rule)
	r.index[key] = struct{}{}
}

func (r *RuleCache[T]) Remove(rules []T) {
	r.Lock()
	defer r.Unlock()
	for _, rule := range rules {
		port := rule.GetRule().Port
		if cachedRules, ok := r.cache[port]; ok {
			newRules := make([]T, 0, len(cachedRules))
			for _, cr := range cachedRules {
				if !utils.IsSameRule(cr.GetRule(), rule.GetRule()) {
					newRules = append(newRules, cr)
				} else {
					delete(r.index, utils.IndexKey(rule.GetRule()))
				}
			}
			if len(newRules) == 0 {
				delete(r.cache, port)
			} else {
				r.cache[port] = newRules
			}
		}
	}
}

func (r *RuleCache[T]) Exists(key string) bool {
	r.RLock()
	defer r.RUnlock()
	_, ok := r.index[key]
	return ok
}

func (r *RuleCache[T]) ToRules() []model.Rule {
	merged := make(map[string]model.Rule)
	r.RLock()
	defer r.RUnlock()

	for _, rules := range r.cache {
		for _, t := range rules {
			rule := t.GetRule()
			key := fmt.Sprintf("%d|%s|%s|%s", rule.Port, rule.Protocol, rule.Action, rule.Chain)

			if existing, ok := merged[key]; ok {
				// 合并 source_ips
				existing.SourceIPs = append(existing.SourceIPs, rule.SourceIPs...)
				merged[key] = existing
			} else {
				merged[key] = rule
			}
		}
	}
	// 转回数组
	result := make([]model.Rule, 0, len(merged))
	for _, rule := range merged {
		result = append(result, rule)
	}
	return result
}

func (r *RuleCache[T]) saveRulesToFileUnlocked(filePath string) error {
	rules := r.ToRules()
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

func (r *RuleCache[T]) EditRuleGeneric(
	ctx context.Context,
	edit model.EditRuleRequest,
	deleteFunc func(ctx context.Context, req model.RuleRequest) error,
	addFunc func(ctx context.Context, req model.RuleRequest) error,
	logPrefix string,
) error {
	rule := model.Rule(edit.Old)
	for _, ip := range rule.SourceIPs {
		singleRule := rule
		singleRule.SourceIPs = []string{ip}
		if !r.Exists(utils.IndexKey(singleRule)) {
			return fmt.Errorf("[%s] 编辑的规则不存在: %+v", logPrefix, singleRule)
		}
	}
	if err := deleteFunc(ctx, edit.Old); err != nil {
		return err
	}
	if err := addFunc(ctx, edit.New); err != nil {
		return err
	}
	logs.InfoCtx(ctx, fmt.Sprintf("[%s] 编辑规则", logPrefix),
		zap.Any("oldRule", edit.Old),
		zap.Any("newRule", edit.New))
	return nil
}
