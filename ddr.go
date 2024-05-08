package resolv

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/syslab-wm/netx"
)

// SVCB records for a DNS service identified as dns1.example.com would be queried at _dns.dns1.example.com.
// https://www.rfc-editor.org/rfc/rfc9461.html
// https://www.rfc-editor.org/rfc/rfc9462.html: Discovery of Designated // Rsolvers

type DesignatedResolver struct {
	Nameserver *Nameserver
	ARPA       []*dns.SVCB
	Under      []*dns.SVCB
}

func GetResolverARPA(nameserverAddr string) []*dns.SVCB {
	c := &Client{}
	c.Transport = &Do53UDP{
		Server: netx.TryJoinHostPort(nameserverAddr, "53"),
	}

	req := c.NewMsg("_dns.resolver.arpa", dns.TypeSVCB)
	resp, err := c.Exchange(req)
	if err != nil {
		return nil
	}

	return CollectRRs[*dns.SVCB](resp.Answer)
}

// TODO: return an error
func (c *Client) GetDesignatedResolvers(domainname string) []*DesignatedResolver {
	var ddrs []*DesignatedResolver

	nameservers, err := c.GetNameservers(domainname)
	if err != nil {
		return nil
	}

	for _, nameserver := range nameservers {
		ddr := new(DesignatedResolver)
		ddr.Nameserver = nameserver
		ddr.ARPA = GetResolverARPA(nameserver.Addrs[0].String())

		name := fmt.Sprintf("_dns.%s", nameserver.Name)
		req := c.NewMsg(name, dns.TypeSVCB)
		req.RecursionDesired = false
		resp, err := c.Exchange(req)
		if err == nil {
			ddr.Under = CollectRRs[*dns.SVCB](resp.Answer)
		}

		if ddr.ARPA != nil || ddr.Under != nil {
			ddrs = append(ddrs, ddr)
		}
	}

	return ddrs
}
