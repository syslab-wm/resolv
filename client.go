package resolv

import (
	"net/netip"

	"github.com/miekg/dns"
	"github.com/syslab-wm/mu"
)

// A Client defines the settings for a DNS client: the tranport, and the
// query settings that are agnostic to the choice of transport.
//
// A program can modify a Client's settings in between queries.   If a program
// wants to modify the Tranport, it should first call the Client's Close
// method, modify (or assign a new Transport), and then resume using the
// Client.
type Client struct {
	// Set the AD ("authentic data") bit in queries. Note that DNS only uses
	// this bit in responses; setting the bit in a query is undefined, though
	// harmless.  Per RFC 3655, a response sets the AD if the DNS server
	// successfully validated the response as per DNSSEC.  If the server did
	// not attempt to validate the records in the response, or validation
	// failed, the bit is 0.
	AD bool

	// Set the CD ("checking disabled") bit in queries.  If the CD bit is set,
	// then the DNS server may omit DNSSEC validation.  A client would
	// generally set the CD bit when it intends to perform DNSSEC validation
	// itself.  If the query clears the bit, the server may perform perform
	// DNSSEC validation.
	CD bool

	// Set the DO ("DNSSEC OK") bit in queries.  The DO bit indicates that the
	// client is DNSSEC-aware and it is OK for the DNS server to return DNSSEC
	// records in a response.  If the bit is cleared, and the server  should
	// not return DNSSEC records in the response.
	DO bool // DNSSEC

	// Set the RD ("recursion deisred") bit in queries.  This indicates that
	// the DNS server should follow all delegations and resolve the query on
	// behalf of the client.
	RD bool

	// Send an EDNS0 Client Subnet option (RFC 7871) in queries.  Either
	// clients or recursive resolvers may add this option.  A prefix with
	// length 0 is indicates a client opt-opt: the recursive resolvers must not
	// add the this option when serviving the client's request.
	ClientSubnet netip.Prefix

	// Send the ENDS0 Name Server Identifier (NSID) option (RFC 5001) in
	// queries.  If a server supports the option, it will return its unique
	// server identifer in the response.  Per RFC 5001, "The semantics of an
	// NSID request are not transitive.  That is: the presence of an NSID
	// option in a query is a request that the name server which receives the
	// query identify itself."
	NSID bool

	// The maximum number of times the client may issue a new query when
	// resolving a chain of CNAMEs.  The client always inspects the CNAMES in a
	// given response to determine if these CNAMEs resolve to the requested record
	// type.  If the chain of CNAMEs in a response terminates in a CNAME
	// record, only then does the client re-issue the query, replacing the
	// original QNAME with the last CNAME target in the chain.
	MaxCNAMEs int

	// The underlying tranport (e.g., [Do53UDP], [Do53TCP], [DoT], [DoH])
	Transport Transport
}

func (c *Client) usesEDNS0() bool {
	if c.DO || c.NSID || c.ClientSubnet.IsValid() {
		return true
	}
	return false
}

// NewMsg creates a new *[github.com/miekg/dns.Msg] based on the client's settings.  The name
// parameter is the query's QNAME (a domainname), and qtype is the
// query type (e.g., [github.com/miekg/dns.TypeA]).  NewMSG fully-qualifies the name before
// constructing the query message, if it is not already fully-qualified.
func (c *Client) NewMsg(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)

	m.RecursionDesired = c.RD
	m.AuthenticatedData = c.AD
	m.CheckingDisabled = c.CD

	if c.usesEDNS0() {
		m.SetEdns0(DefaultUDPBufSize, c.DO)
		if c.NSID {
			AddEDNS0NSID(m)
		}
		if c.ClientSubnet.IsValid() {
			AddEDNS0Subnet(m, c.ClientSubnet)
		}
	}

	return m
}

// Exchange performs a synchronous DNS query: it sends the message req and
// waits for a response.  The client settings (along with the client's
// transport's settings) determine whether (and how) to retry a query in case
// of an error response.
//
// If there is a va
func (c *Client) Exchange(req *dns.Msg) (*dns.Msg, error) {
	var err error
	var cnames []*dns.CNAME
	var resp *dns.Msg
	qtype := req.Question[0].Qtype

	// if following CNAMES, req will change; thus, make a copy so it
	// doesn't affect the caller
	if c.MaxCNAMEs > 0 {
		req = req.Copy()
	}

	for i := 0; i <= c.MaxCNAMEs; i++ {
		resp, err = c.Transport.Exchange(req)
		if err != nil {
			return nil, err // TODO: when would this ever have a resp to return?
		}
		if resp.Rcode != dns.RcodeSuccess {
			return resp, ErrRcode
		}

		// gather all RRs that are of the qtype
		var ans []dns.RR
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype == qtype {
				ans = append(ans, rr)
				// if such an RR matches the name we're searching for, it's a
				// direct hit
				if rr.Header().Name == req.Question[0].Name {
					return resp, nil
				}
			}
		}

		// get all of the CNAMES from the answer
		cnames = CollectRRs[*dns.CNAME](resp.Answer)
		if len(cnames) == 0 {
			return resp, ErrNoData
		}

		// validate that the CNAMEs form a chain
		ordered := OrderCNAMEs(cnames)
		if !ordered {
			return resp, ErrInvalidCNAMEs

		}
		// the head of the chain must match the name we're searching for
		if cnames[0].Hdr.Name != req.Question[0].Name {
			return resp, ErrInvalidCNAMEs
		}

		// Is the last CNAME in the chain an alias for an RR of the
		// type we're searching for?  If so, success.
		lastCNAME := cnames[len(cnames)-1]
		for _, rr := range ans {
			if lastCNAME.Target == rr.Header().Name {
				return resp, nil
			}
		}

		if len(ans) > 0 {
			// weird case: response has record(s) of the type we're searching
			// for, but none correspond to the name we're querying or one of
			// its CNAME aliases.
			return resp, ErrBadName
		}

		// setup to repeat query on the last CNAME in the chain
		req.SetQuestion(dns.Fqdn(cnames[len(cnames)-1].Target), qtype)
	}

	if len(cnames) > 0 {
		return resp, ErrMaxCNAMEs
	}

	// UNREACHABLE
	mu.BUG("reached what should be unreachable code: req: %v, resp: %v", req, resp)
	return resp, ErrNoData
}

// Lookup is convenience method that creates a new message and
// then issues a synchronous query with that message.
func (c *Client) Lookup(name string, qtype uint16) (*dns.Msg, error) {
	req := c.NewMsg(name, qtype)
	return c.Exchange(req)
}

func (c *Client) Close() error {
	return c.Transport.Close()
}
