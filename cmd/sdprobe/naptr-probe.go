package main

import (
	"github.com/miekg/dns"
	"github.com/syslab-wm/resolv"
)

type NAPTRData struct {
	Order       uint16
	Preference  uint16
	Flags       string
	Service     string
	Regexp      string
	Replacement string
}

type NAPTRProbeResult struct {
	Records []*NAPTRData
}

func NewNAPTRProbeResult() *NAPTRProbeResult {
	r := new(NAPTRProbeResult)
	return r
}

func DoNAPTRProbe(c *resolv.Client, domain string) *NAPTRProbeResult {
	r := NewNAPTRProbeResult()

	resp, err := c.Lookup(domain, dns.TypeNAPTR)
	if err != nil {
		return nil
	}

	naptrs := resolv.CollectRRs[*dns.NAPTR](resp.Answer)
	for _, naptr := range naptrs {
		r.Records = append(r.Records, &NAPTRData{
			Order:       naptr.Order,
			Preference:  naptr.Preference,
			Flags:       naptr.Flags,
			Service:     naptr.Service,
			Regexp:      naptr.Regexp,
			Replacement: naptr.Replacement,
		})
	}

	return r
}
