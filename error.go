package resolv

type Error struct{ err string }

func (e *Error) Error() string {
	if e == nil {
		return "resolv: <nil>"
	}
	return "resolv: " + e.err
}

// These are errors that a client's Exchange method may return.
var (
	// ErrRcode indicates that the DNS response has an RCODE that is not
	// NOERROR ([github.com/miekg/dns.RcodeSuccess]).
	ErrRcode error = &Error{err: "response rcode is not success"} // DNS response's rcode is something other than Sucess

	// ErrNoData represents the NODATA pseudo RCODE.  NODATA is not a real
	// RCODE, but rather describes a response with an RCODE of NOERROR and zero
	// answers.  A DNS server sends such a response when it has records for the
	// domain, but not of the type the client requested.
	ErrNoData error = &Error{err: "response has a NODATA pseudo RCODE"}

	// ErrInvalidCNAMEChain indicates that the response's answer contains
	// an invalid set of CNAMEs.  There are several ways that the CNAME(s)
	// could be invalid, such as if the CNAMEs cannot be ordered to form a
	// logical chain, or if the first CNAME record's name does not match
	// the query's QNAME.  This type of error should be rare.
	ErrInvalidCNAMEs error = &Error{err: "response contains an invalid CNAME chain"}

	// ErrBadName indicates that the response's answer contains records that
	// match the query's QTYPE, but none of the records match the QNAME or one
	// of the QNAME's CNAME aliases.  This type of error should be rare.
	ErrBadName error = &Error{err: "response has an answer that matches neither the qname nor one of its aliases"}

	// ErrBadAnswer indicates that the response's answer contains data that does not conform to
	// its RR type.  This type of error should be rare.
	ErrBadData error = &Error{err: "response has an answer the data does not conform to the RR type"}

	// ErrMaxCNAMEs indicates that the client followed its configurd maximum number of
	// CNAMEs without resolving the query.
	ErrMaxCNAMEs error = &Error{err: "query followed max number of CNAMEs"}
)
