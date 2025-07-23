package utils

import (
	"firewall-manager/common/common"
	"firewall-manager/model"
	"go.uber.org/zap"
	"regexp"
	"strconv"
	"strings"
)

var iptablesRegex = regexp.MustCompile(
	`^-A\s+(\S+)` + // 1: Chain
		`(?:.*?-s\s+([0-9./]+))?` + // 2: Source IP（可选）
		`(?:.*?-d\s+([0-9./]+))?` + // 3: Destination IP（可选）
		`(?:.*?-p\s+(\w+))?` + // 4: Protocol（可选）
		`(?:.*?--dport\s+(\d+))?` + // 5: Port（可选）
		`.*?-j\s+(\w+)`, // 6: Action
)
var firewalldRegex = regexp.MustCompile(`rule family="(ipv4|ipv6)"(?: source address="([^"]+)")?(?: destination address="([^"]+)")?(?: port port="(\d+)" protocol="(tcp|udp)")? (accept|reject|drop)`)
var ufwV4Regex = regexp.MustCompile(`^\s*\[\s*(\d+)\]\s+(.+?)\s+([A-Z]+)\s+([A-Z]+)\s+((?:Anywhere\s*)|(?:[\d\.]+(?:/\d+)?))\s*$`)
var portProtoRegex = regexp.MustCompile(`^(\d+)(?:/([a-z]+))?$`)

func IptablesParseRules(lines []string) []model.IptablesRule {
	var parsed []model.IptablesRule
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A") {
			continue
		}

		matches := iptablesRegex.FindStringSubmatch(line)
		if len(matches) < 7 {
			continue
		}

		port, _ := strconv.Atoi(matches[5])
		sourceIP := FirstNonEmpty(matches[2], matches[3], common.DefaultIP)
		r := model.Rule{
			Protocol:  strings.ToLower(matches[4]),
			Port:      port,
			Action:    strings.ToUpper(matches[6]),
			Chain:     strings.ToUpper(matches[1]),
			SourceIPs: []string{sourceIP},
		}

		// 过滤无效规则
		if r.Port == 0 || r.Protocol == "" || r.Protocol == "icmp" || r.Action == "" || r.Chain == "" {
			continue
		}
		if r.Action == "CHECKSUM" && r.Chain == "POSTROUTING" && r.Protocol == "udp" && r.Port == 68 {
			continue
		}

		parsed = append(parsed, model.IptablesRule{Rule: r, Raw: line})
	}
	return parsed
}

func RichRuleParse(line string) (model.FWRule, bool) {
	m := firewalldRegex.FindStringSubmatch(line)
	if len(m) == 0 {
		return model.FWRule{}, false
	}
	port := 0
	if m[4] != "" {
		port, _ = strconv.Atoi(m[4])
	}

	// 方向判断：source → in，destination → out
	direction := "INPUT"
	if m[3] != "" {
		direction = "OUTPUT"
	}

	return model.FWRule{
		Rule: model.Rule{
			SourceIPs: []string{FirstNonEmpty(m[2], m[3], common.DefaultIP)},
			Port:      port,
			Protocol:  m[5],
			Action:    strings.ToUpper(m[6]),
			Chain:     direction,
		},
		Type: common.RICHRULE,
	}, true
}

func ExtractPortAndProtocol(service string) (int, string) {
	if port, exists := common.ServiceToPortMap[strings.ToUpper(service)]; exists {
		service = port
	}
	// 处理标准格式 "端口/协议"
	if matches := portProtoRegex.FindStringSubmatch(service); len(matches) > 0 {
		port, err := strconv.Atoi(matches[1])
		if err != nil {
			zap.L().Warn("解析服务端口失败", zap.String("service", service))
			return 0, ""
		}

		protocol := matches[2]
		if protocol == "" {
			protocol = "tcp" // 默认使用TCP
		}

		return port, protocol
	}

	// 处理特殊情况 (如 mDNS, 多播地址等)
	if strings.Contains(service, "mDNS") {
		return 5353, "udp"
	}

	// 无法解析端口，返回0
	zap.L().Warn("[ufw] 无法解析端口", zap.String("service", service))
	return 0, ""
}

func UFWParseRules(lines []string) []model.Rule {
	var parsed []model.Rule
	for _, line := range lines {
		if matches := ufwV4Regex.FindStringSubmatch(line); len(matches) >= 6 {
			service := matches[2]
			action := common.UFWActionMap[strings.ToUpper(matches[3])]
			chain := common.UFWChainMap[strings.ToUpper(matches[4])]
			source := matches[5]
			if strings.TrimSpace(source) == "Anywhere" {
				source = common.DefaultIP
			}
			port, protocol := ExtractPortAndProtocol(service)
			r := model.Rule{
				Port:      port,
				Protocol:  protocol,
				Action:    action,
				Chain:     chain,
				SourceIPs: []string{source},
			}
			parsed = append(parsed, r)
		}
	}
	return parsed
}
