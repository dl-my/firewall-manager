package utils

import (
	"firewall-manager/common/common"
	"firewall-manager/model"
	"fmt"
	"strings"
)

func IsSameRule(a, b model.Rule) bool {
	return a.Port == b.Port &&
		strings.EqualFold(a.Protocol, b.Protocol) &&
		strings.EqualFold(a.Action, b.Action) &&
		strings.EqualFold(a.Chain, b.Chain) &&
		sameStringSlice(a.SourceIPs, b.SourceIPs)
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func GetServiceByPort(port int, protocol string) string {
	key := fmt.Sprintf("%d/%s", port, strings.ToLower(protocol))
	if s, ok := common.PortToServiceMap[key]; ok {
		return s
	}
	return ""
}

func FirstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func IndexKey(r model.Rule) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%d|%s|%s|%s|", r.Port,
		strings.ToLower(r.Protocol),
		strings.ToLower(r.Action),
		strings.ToLower(r.Chain),
	))
	if len(r.SourceIPs) > 0 && r.SourceIPs[0] != "" {
		b.WriteString(r.SourceIPs[0])
	} else {
		b.WriteString(common.DefaultIP)
	}
	return b.String()
}
