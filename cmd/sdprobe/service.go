package main

import (
	"github.com/miekg/dns"
	"github.com/syslab-wm/resolv"
)

// ServiceInstanceInfo is the aggregation of SRV, TXT, and A/AAAA records.
// The core difference between this struct and [resolv.ServiceInstanceInfoX] is
// the addition of fields that indicate whether the SRV and A/AAAA records are
// DNSEEC-validated
type ServiceInstanceInfoX struct {
	resolv.ServiceInstanceInfo
	// SRV record(s) DNSSEC validation
	SrvValidated DNSSECValidationResult
	// A record(s) DNSSEC validation
	AValidated DNSSECValidationResult
	// AAAA record(s) DNSSEC validation
	AAAAValidated DNSSECValidationResult
}

func InfoXFromInfo(info *resolv.ServiceInstanceInfo) *ServiceInstanceInfoX {
	x := ServiceInstanceInfoX{}
	x.ServiceInstanceInfo = *info
	return &x
}

func (info *ServiceInstanceInfoX) CheckDNSSECValidation(c *resolv.Client) {
	info.SrvValidated = CheckDNSSECValidation(c, info.Name, dns.TypeSRV)
	info.AValidated = CheckDNSSECValidation(c, info.Target, dns.TypeA)
	info.AAAAValidated = CheckDNSSECValidation(c, info.Target, dns.TypeAAAA)
}
