package main

import (
	"fmt"

	"github.com/syslab-wm/resolv"
)

type PTRProbeResult struct {
	Services map[string][]*resolv.ServiceInstanceInfo
}

func NewPTRProbeResult() *PTRProbeResult {
	r := new(PTRProbeResult)
	r.Services = make(map[string][]*resolv.ServiceInstanceInfo)
	return r
}

func DoPTRProbe(c *resolv.Client, domain string) *PTRProbeResult {
	var foundFlag bool
	r := NewPTRProbeResult()

	for _, service := range Services {
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

			r.Services[service] = append(r.Services[service], info)
			foundFlag = true
		}
	}

	if foundFlag {
		return r
	}
	return nil
}
