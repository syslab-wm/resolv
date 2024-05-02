package main

import (
	"log"
	"strings"

	"github.com/syslab-wm/adt/set"
	"github.com/syslab-wm/resolv"
)

type DNSSDProbeResult struct {
	ServiceBrowsers       []string
	DefaultServiceBrowser string
	LegacyServiceBrowsers []string
	Services              map[string][]*resolv.ServiceInstanceInfo
}

func NewDNSSDProbeResult() *DNSSDProbeResult {
	r := new(DNSSDProbeResult)
	r.Services = make(map[string][]*resolv.ServiceInstanceInfo)
	return r
}

func IsValidDomain(domain string) bool {
	if domain == "visit.keznews.com." {
		return false
	}
	if strings.HasSuffix(domain, ".localhost.") {
		return false
	}
	if strings.HasSuffix(domain, ".searchreinvented.com.") {
		return false
	}
	if strings.HasSuffix(domain, ".ztomy.com.") {
		return false
	}
	if strings.HasSuffix(domain, ".klczy.com.") {
		return false
	}
	return true
}

func DoDNSSDProbe(c *resolv.Client, domain string) *DNSSDProbeResult {
	var err error
	var foundFlag bool
	r := NewDNSSDProbeResult()
	browserSet := set.New[string]()

	r.ServiceBrowsers, err = c.GetServiceBrowserDomains(domain)
	if err != nil {
		browserSet.Add(r.ServiceBrowsers...)
	}
	r.DefaultServiceBrowser, err = c.GetDefaultServiceBrowserDomain(domain)
	if err != nil {
		browserSet.Add(r.DefaultServiceBrowser)
	}
	r.LegacyServiceBrowsers, err = c.GetLegacyServiceBrowserDomains(domain)
	if err != nil {
		browserSet.Add(r.LegacyServiceBrowsers...)
	}

	if !browserSet.Has(domain) {
		browserSet.Add(domain)
	}

	for _, browser := range browserSet.Items() {
		if !IsValidDomain(browser) {
			continue
		}
		services, err := c.GetServices(browser)
		if err != nil {
			continue
		}

		for _, service := range services {
			if !IsValidDomain(service) {
				continue
			}
			instances, err := c.GetServiceInstances(service)
			if err != nil {
				continue
			}

			for _, instance := range instances {
				info, err := c.GetServiceInstanceInfo(instance)
				if err != nil {
					continue
				}

				_, serviceName, _ := resolv.ParseInstanceServiceDomain(instance)
				if serviceName == "" {
					log.Printf("Cannot parse service name for %q", instance)
					continue
				}

				// TODO: Is it possible that multiple browsers could return the
				// same service instance?  Should you dedup on instance.Target?
				r.Services[serviceName] = append(r.Services[serviceName], info)
				foundFlag = true
			}
		}
	}

	if foundFlag {
		return r
	}
	return nil
}
