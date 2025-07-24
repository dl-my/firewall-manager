package common

var (
	IPKey             = "operator_ip"
	UFWRulesFile      = "ufw_rules.json"
	FWRulesFile       = "firewalld_rules.json"
	IptablesRulesFile = "iptables_rules.json"

	FWCMD     = "firewall-cmd"
	PERMANENT = "--permanent"

	PORT     = "port"
	SERVICE  = "service"
	RICHRULE = "rich-rule"
	IPV4     = "ipv4"
	Add      = "add"
	Delete   = "delete"

	IptablesTable = "filter"

	DefaultIP           = "0.0.0.0/0"
	IptablesPath        = "iptables"
	IptablesRestorePath = "iptables-restore"

	UFWActionMap = map[string]string{
		"ACCEPT": "ALLOW",
		"ALLOW":  "ALLOW",
		"DROP":   "DENY",
		"DENY":   "DENY",
		"REJECT": "DENY",
	}

	UFWChainMap = map[string]string{
		"IN":     "INPUT",
		"INPUT":  "INPUT",
		"OUT":    "OUTPUT",
		"OUTPUT": "OUTPUT",
		"":       "INPUT",
	}
	ServiceToPortMap = map[string]string{
		"SSH":           "22/tcp",
		"HTTP":          "80/tcp",
		"HTTPS":         "443/tcp",
		"SMTP":          "25/tcp",
		"POP3":          "110/tcp",
		"IMAP":          "143/tcp",
		"DHCPV6-CLIENT": "546/udp",
	}
	PortToServiceMap = map[string]string{
		"22/tcp":  "SSH",
		"80/tcp":  "HTTP",
		"443/tcp": "HTTPS",
		"25/tcp":  "SMTP",
		"110/tcp": "POP3",
		"143/tcp": "IMAP",
		"546/udp": "DHCPV6-CLIENT",
	}
)
