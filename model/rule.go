package model

type Rule struct {
	Port      int      `json:"port"`       // 端口号
	Protocol  string   `json:"protocol"`   // 协议类型
	Action    string   `json:"action"`     // 动作类型
	Chain     string   `json:"chain"`      // 规则链
	SourceIPs []string `json:"source_ips"` // 源IP列表
}

type IptablesRule struct {
	Table string      `json:"table"`
	Rule  RuleRequest `json:"rule"`
}

// 用于Add/Delete/Edit请求
type RuleRequest Rule

// 用于编辑规则
type EditRuleRequest struct {
	Old RuleRequest `json:"old"`
	New RuleRequest `json:"new"`
}
