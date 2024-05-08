package main

import (
	"fmt"

	"github.com/syslab-wm/resolv"
)

type PTRProbeResult struct {
	Services map[string][]*ServiceInstanceInfoX
}

func NewPTRProbeResult() *PTRProbeResult {
	r := new(PTRProbeResult)
	r.Services = make(map[string][]*ServiceInstanceInfoX)
	return r
}

func DoPTRProbe(c *resolv.Client, domain string, serviceNames []string) *PTRProbeResult {
	var foundFlag bool
	r := NewPTRProbeResult()

	for _, service := range serviceNames {
		name := fmt.Sprintf("%s.%s", service, domain)
		instances, err := c.GetServiceInstances(name)
		if err != nil {
			continue
		}

		for _, instance := range instances {
			if !IsValidDomain(instance) {
				continue
			}

			info, err := c.GetServiceInstanceInfo(instance)
			if err != nil {
				continue
			}
			infox := InfoXFromInfo(info)
			infox.CheckDNSSECValidation(c)

			r.Services[service] = append(r.Services[service], infox)
			foundFlag = true
		}
	}

	if foundFlag {
		return r
	}
	return nil
}
