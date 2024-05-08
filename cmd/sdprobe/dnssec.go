package main

import (
	"log"

	"github.com/miekg/dns"
	"github.com/syslab-wm/resolv"
)

// DNNSECValidationResult is the rewsult of validating a specific DNS record.
type DNSSECValidationResult struct {
	Validated bool
	Rcode     int
	// Only set if Validated=false
	ExtendedErrorCode uint16
}

func CheckDNSSECValidation(c *resolv.Client, name string, qtype uint16) DNSSECValidationResult {
	result := DNSSECValidationResult{Rcode: -1}

	origDO := c.DO
	origAD := c.AD
	origCD := c.CD
	defer func() {
		// restore header flags
		c.DO = origDO
		c.AD = origAD
		c.CD = origCD
	}()

	c.DO = true
	c.AD = true
	c.CD = false
	resp, err := c.Lookup(name, qtype)
	if resp == nil {
		// network error
		return result
	}

	if err != nil && err != resolv.ErrRcode && err != resolv.ErrNoData {
		// CNAME processing error or unexpected response data
		return result
	}

	result.Rcode = resp.Rcode

	if resp.AuthenticatedData {
		result.Validated = true
		return result
	}

	opts := resolv.CollectRRs[*dns.OPT](resp.Extra)
	if len(opts) > 0 {
		// there should only be one OPT record
		opt := opts[0]
		for _, s := range opt.Option {
			switch e := s.(type) {
			case *dns.EDNS0_EDE:
				// There can be multiple ExtendedErrorCode options, but
				// this is unlikely; thus, stop at the first one
				result.ExtendedErrorCode = e.InfoCode
				log.Printf("name: %s, InfoCode: %d, EDE: %s", name, e.InfoCode, e.ExtraText)
				break
			default:
				continue
			}
		}
	}

	if err == nil && result.ExtendedErrorCode == 0 {
		rrsigs := resolv.CollectRRs[*dns.RRSIG](resp.Answer)
		if len(rrsigs) == 0 {
			// There is already a dns.ExtendedErrorCodeRRSIGsMissing;
			// this is our own version that says we got a response withi
			// NoError and AD=0 that did not have any RRSIGs in the answer.
			// TODO: should we also check the extra section (for NSEC3 and
			// RRIGS?)
			result.ExtendedErrorCode = 1000
		}
	}

	// There was some sort of network error
	return result
}
