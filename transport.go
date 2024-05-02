package resolv

import (
	"github.com/miekg/dns"
)

type Transport interface {
	Exchange(*dns.Msg) (*dns.Msg, error)
	Close() error
}
