package resolv

import (
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
)

type Do53UDP struct {
	Server           string
	IPv4Only         bool
	IPv6Only         bool
	Timeout          time.Duration
	UDPBufSize       int
	IgnoreTruncation bool

	client *dns.Client
	conn   *dns.Conn
}

func (t *Do53UDP) dial() error {
	var err error

	net := "udp"
	if t.IPv4Only {
		net = "udp4"
	}
	if t.IPv6Only {
		net = "udp6"
	}

	t.client = &dns.Client{
		Net:     net,
		Timeout: t.Timeout,
	}

	t.conn, err = t.client.Dial(t.Server)
	if err != nil {
		return fmt.Errorf("failed to connect to DNS server %s: %w", t.Server, err)
	}
	return nil
}

func (t *Do53UDP) Exchange(req *dns.Msg) (*dns.Msg, error) {
	var err error
	var resp *dns.Msg
	// even though this is UDP, from an API perspective, we still have to call dial
	err = t.dial()
	if err != nil {
		return nil, err
	}

	resp, _, err = t.client.ExchangeWithConn(req, t.conn)
	if err != nil {
		return nil, err
	}

	if resp.Truncated && !t.IgnoreTruncation {
		// TODO: we could first try a larger UDP size before falling back to TCP
		log.Printf("truncated response for req %v, retrying over TCP", req)
		tcp := &Do53TCP{
			Server:   t.Server,
			IPv4Only: t.IPv4Only,
			IPv6Only: t.IPv6Only,
			Timeout:  t.Timeout,
			KeepOpen: false,
		}
		return tcp.Exchange(req)
	}

	return resp, nil
}

func (t *Do53UDP) Close() error {
	return nil
}
